//! Connected-stream sendto destination matrix, getpeername, and UDP destination validation probe.
//!
//! Exercises Linux stream destination handling and peername behavior across:
//! 1. Unconnected getpeername across AF_INET stream, AF_INET datagram, and AF_UNIX stream.
//! 2. Connected AF_INET TCP getpeername address family and symmetric endpoint relationship.
//! 3. Connected AF_INET TCP sendto matrix (NULL destination, NULL with positive length,
//!    matching peer destination, foreign destination from probe-owned socket, length 0, length 1,
//!    negative length, oversized length, inaccessible pointer with positive length, and
//!    inaccessible pointer with zero length) verifying payload delivery or move_addr_to_kernel rejection.
//! 4. Adjacent UDP destination validation (negative length, oversized length, zero length, short length 1,
//!    inaccessible pointer with positive length, inaccessible pointer with zero length, and valid destination
//!    with verified delivery to a probe-owned ephemeral UDP receiver).
//! 5. Connected AF_UNIX stream socketpair sendto (NULL destination, supplied destination with length 0
//!    acting as connected send, supplied destination with positive length -> EISCONN,
//!    negative/oversized length -> EINVAL, inaccessible pointer with positive length -> EFAULT,
//!    and inaccessible pointer with zero length) and getpeername family.
//!
//! Output prints actual normalized return codes, exact numeric and symbolic errnos,
//! delivery confirmations, and endpoint relationships without assuming uncertain Linux behavior
//! or leaking ephemeral ports/addresses.
//!
//! All waits and operations use nonblocking sockets and bounded poll deadlines.

use conformance_probes::{errno, report};
use core::mem::{MaybeUninit, size_of};

const INACCESSIBLE_PTR: *const libc::sockaddr = 0x1 as *const libc::sockaddr;

fn errno_repr(err: i32) -> String {
    if err == 0 {
        return "0".to_string();
    }
    let name = match err {
        libc::EAGAIN => "EAGAIN",
        libc::EBADF => "EBADF",
        libc::EFAULT => "EFAULT",
        libc::EINVAL => "EINVAL",
        libc::EISCONN => "EISCONN",
        libc::ENOTCONN => "ENOTCONN",
        libc::EPIPE => "EPIPE",
        libc::EDESTADDRREQ => "EDESTADDRREQ",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EAFNOSUPPORT => "EAFNOSUPPORT",
        libc::ECONNREFUSED => "ECONNREFUSED",
        libc::ECONNRESET => "ECONNRESET",
        libc::EINPROGRESS => "EINPROGRESS",
        libc::ETIMEDOUT => "ETIMEDOUT",
        libc::EEXIST => "EEXIST",
        libc::ENOENT => "ENOENT",
        libc::EPERM => "EPERM",
        libc::EMSGSIZE => "EMSGSIZE",
        _ => "EUNKNOWN",
    };
    format!("{name}:{err}")
}

unsafe fn bounded_recv_exact(fd: i32, expected: &[u8], timeout_ms: u64) -> (usize, i32, bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 128];
    let mut received = 0usize;
    let mut last_err = 0i32;

    while received < expected.len() {
        let now = std::time::Instant::now();
        if now >= deadline {
            last_err = libc::ETIMEDOUT;
            break;
        }
        let rem = deadline.duration_since(now);
        let rem_ms = (rem.as_millis() as i32).max(1);

        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_rc = libc::poll(&mut pfd, 1, rem_ms);
        if poll_rc < 0 {
            let err = errno();
            if err == libc::EINTR {
                continue;
            }
            last_err = err;
            break;
        }
        if poll_rc == 0 {
            last_err = libc::ETIMEDOUT;
            break;
        }

        let to_read = (expected.len() - received).min(buf.len() - received);
        let n = libc::recv(
            fd,
            buf[received..].as_mut_ptr() as *mut libc::c_void,
            to_read,
            libc::MSG_DONTWAIT,
        );
        if n < 0 {
            let err = errno();
            if err == libc::EINTR || err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                continue;
            }
            last_err = err;
            break;
        }
        if n == 0 {
            // Unexpected peer EOF before full payload received
            break;
        }
        received += n as usize;
    }

    let matches = received == expected.len() && &buf[..received] == expected;
    (received, last_err, matches)
}

// -----------------------------------------------------------------------------
// 1. Unconnected getpeername matrix
// -----------------------------------------------------------------------------

unsafe fn test_unconnected_getpeername() {
    // 1.1 Unconnected AF_INET TCP stream socket -> ENOTCONN
    let s_inet_stream = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    let (inet_stream_rc, inet_stream_err) = if s_inet_stream >= 0 {
        let mut ss: libc::sockaddr_storage = MaybeUninit::zeroed().assume_init();
        let mut slen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let rc = libc::getpeername(
            s_inet_stream,
            &mut ss as *mut _ as *mut libc::sockaddr,
            &mut slen,
        );
        let err = if rc < 0 { errno() } else { 0 };
        libc::close(s_inet_stream);
        (rc, err)
    } else {
        let err = errno();
        (-1, err)
    };

    // 1.2 Unconnected AF_INET UDP datagram socket -> ENOTCONN
    let s_inet_dgram = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0);
    let (inet_dgram_rc, inet_dgram_err) = if s_inet_dgram >= 0 {
        let mut ss: libc::sockaddr_storage = MaybeUninit::zeroed().assume_init();
        let mut slen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let rc = libc::getpeername(
            s_inet_dgram,
            &mut ss as *mut _ as *mut libc::sockaddr,
            &mut slen,
        );
        let err = if rc < 0 { errno() } else { 0 };
        libc::close(s_inet_dgram);
        (rc, err)
    } else {
        let err = errno();
        (-1, err)
    };

    // 1.3 Unconnected AF_UNIX stream socket -> ENOTCONN
    let s_unix_stream = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    let (unix_stream_rc, unix_stream_err) = if s_unix_stream >= 0 {
        let mut ss: libc::sockaddr_storage = MaybeUninit::zeroed().assume_init();
        let mut slen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let rc = libc::getpeername(
            s_unix_stream,
            &mut ss as *mut _ as *mut libc::sockaddr,
            &mut slen,
        );
        let err = if rc < 0 { errno() } else { 0 };
        libc::close(s_unix_stream);
        (rc, err)
    } else {
        let err = errno();
        (-1, err)
    };

    report!(
        unconnected_inet_stream_getpeername_rc = inet_stream_rc,
        unconnected_inet_stream_getpeername_errno = errno_repr(inet_stream_err),
        unconnected_inet_dgram_getpeername_rc = inet_dgram_rc,
        unconnected_inet_dgram_getpeername_errno = errno_repr(inet_dgram_err),
        unconnected_unix_stream_getpeername_rc = unix_stream_rc,
        unconnected_unix_stream_getpeername_errno = errno_repr(unix_stream_err),
    );
}

// -----------------------------------------------------------------------------
// 2. Connected AF_INET TCP getpeername & sendto matrix
// -----------------------------------------------------------------------------

unsafe fn test_connected_inet_stream_matrix() {
    let listen_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    if listen_fd < 0 {
        let err = errno();
        report!(tcp_setup_ok = false, tcp_setup_errno = errno_repr(err));
        return;
    }

    let mut bind_addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    bind_addr.sin_family = libc::AF_INET as libc::sa_family_t;
    bind_addr.sin_addr.s_addr = 0x7f000001u32.to_be(); // 127.0.0.1
    bind_addr.sin_port = 0; // ephemeral

    let b_rc = libc::bind(
        listen_fd,
        &bind_addr as *const _ as *const libc::sockaddr,
        size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    if b_rc != 0 {
        let err = errno();
        libc::close(listen_fd);
        report!(tcp_setup_ok = false, tcp_setup_errno = errno_repr(err));
        return;
    }

    let l_rc = libc::listen(listen_fd, 5);
    if l_rc != 0 {
        let err = errno();
        libc::close(listen_fd);
        report!(tcp_setup_ok = false, tcp_setup_errno = errno_repr(err));
        return;
    }

    let mut server_listen_addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    let mut server_listen_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let gs_rc = libc::getsockname(
        listen_fd,
        &mut server_listen_addr as *mut _ as *mut libc::sockaddr,
        &mut server_listen_len,
    );
    if gs_rc != 0 {
        let err = errno();
        libc::close(listen_fd);
        report!(tcp_setup_ok = false, tcp_setup_errno = errno_repr(err));
        return;
    }

    // Bind a second probe-owned ephemeral loopback socket to act as foreign destination
    let foreign_listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    if foreign_listener < 0 {
        let err = errno();
        libc::close(listen_fd);
        report!(tcp_setup_ok = false, tcp_setup_errno = errno_repr(err));
        return;
    }

    let mut foreign_bind_addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    foreign_bind_addr.sin_family = libc::AF_INET as libc::sa_family_t;
    foreign_bind_addr.sin_addr.s_addr = 0x7f000001u32.to_be();
    foreign_bind_addr.sin_port = 0;

    let fb_rc = libc::bind(
        foreign_listener,
        &foreign_bind_addr as *const _ as *const libc::sockaddr,
        size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    if fb_rc != 0 {
        let err = errno();
        libc::close(foreign_listener);
        libc::close(listen_fd);
        report!(tcp_setup_ok = false, tcp_setup_errno = errno_repr(err));
        return;
    }

    let mut foreign_addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    let mut foreign_addr_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let fgs_rc = libc::getsockname(
        foreign_listener,
        &mut foreign_addr as *mut _ as *mut libc::sockaddr,
        &mut foreign_addr_len,
    );
    if fgs_rc != 0 {
        let err = errno();
        libc::close(foreign_listener);
        libc::close(listen_fd);
        report!(tcp_setup_ok = false, tcp_setup_errno = errno_repr(err));
        return;
    }

    let client_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    if client_fd < 0 {
        let err = errno();
        libc::close(foreign_listener);
        libc::close(listen_fd);
        report!(tcp_setup_ok = false, tcp_setup_errno = errno_repr(err));
        return;
    }

    let c_rc = libc::connect(
        client_fd,
        &server_listen_addr as *const _ as *const libc::sockaddr,
        server_listen_len,
    );
    let mut connect_err = 0i32;
    let mut connect_ok = false;
    if c_rc == 0 {
        connect_ok = true;
    } else {
        let err = errno();
        if err == libc::EINPROGRESS {
            let mut pfd = libc::pollfd {
                fd: client_fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let p_rc = libc::poll(&mut pfd, 1, 500);
            if p_rc == 1 {
                let mut so_err: i32 = -1;
                let mut so_len = size_of::<i32>() as libc::socklen_t;
                let opt_rc = libc::getsockopt(
                    client_fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    &mut so_err as *mut _ as *mut libc::c_void,
                    &mut so_len,
                );
                if opt_rc == 0 {
                    if so_err == 0 {
                        connect_ok = true;
                    } else {
                        connect_err = so_err;
                    }
                } else {
                    connect_err = errno();
                }
            } else if p_rc == 0 {
                connect_err = libc::ETIMEDOUT;
            } else {
                connect_err = errno();
            }
        } else {
            connect_err = err;
        }
    }

    if !connect_ok {
        libc::close(client_fd);
        libc::close(foreign_listener);
        libc::close(listen_fd);
        report!(
            tcp_setup_ok = false,
            tcp_setup_errno = errno_repr(connect_err)
        );
        return;
    }

    let mut pfd_l = libc::pollfd {
        fd: listen_fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let p_l = libc::poll(&mut pfd_l, 1, 500);
    let mut accept_err = 0i32;
    let mut server_fd = -1;
    if p_l == 1 {
        let mut accepted_peer_addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
        let mut accepted_peer_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        server_fd = libc::accept4(
            listen_fd,
            &mut accepted_peer_addr as *mut _ as *mut libc::sockaddr,
            &mut accepted_peer_len,
            libc::SOCK_NONBLOCK,
        );
        if server_fd < 0 {
            accept_err = errno();
        }
    } else if p_l == 0 {
        accept_err = libc::ETIMEDOUT;
    } else {
        accept_err = errno();
    }

    if server_fd < 0 {
        libc::close(client_fd);
        libc::close(foreign_listener);
        libc::close(listen_fd);
        report!(
            tcp_setup_ok = false,
            tcp_setup_errno = errno_repr(accept_err)
        );
        return;
    }

    report!(tcp_setup_ok = true, tcp_setup_errno = errno_repr(0));

    // 2.1 Connected TCP getpeername & endpoint symmetry
    let mut client_local: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    let mut client_local_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let c_loc_rc = libc::getsockname(
        client_fd,
        &mut client_local as *mut _ as *mut libc::sockaddr,
        &mut client_local_len,
    );

    let mut client_peer: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    let mut client_peer_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let c_peer_rc = libc::getpeername(
        client_fd,
        &mut client_peer as *mut _ as *mut libc::sockaddr,
        &mut client_peer_len,
    );
    let c_peer_err = if c_peer_rc < 0 { errno() } else { 0 };

    let mut server_local: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    let mut server_local_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let s_loc_rc = libc::getsockname(
        server_fd,
        &mut server_local as *mut _ as *mut libc::sockaddr,
        &mut server_local_len,
    );

    let mut server_peer: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    let mut server_peer_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let s_peer_rc = libc::getpeername(
        server_fd,
        &mut server_peer as *mut _ as *mut libc::sockaddr,
        &mut server_peer_len,
    );
    let s_peer_err = if s_peer_rc < 0 { errno() } else { 0 };

    let client_peer_fam_inet = c_peer_rc == 0 && (client_peer.sin_family as i32 == libc::AF_INET);
    let server_peer_fam_inet = s_peer_rc == 0 && (server_peer.sin_family as i32 == libc::AF_INET);

    let client_peer_matches_server_local = c_peer_rc == 0
        && s_loc_rc == 0
        && client_peer.sin_addr.s_addr == server_local.sin_addr.s_addr
        && client_peer.sin_port == server_local.sin_port;

    let server_peer_matches_client_local = s_peer_rc == 0
        && c_loc_rc == 0
        && server_peer.sin_addr.s_addr == client_local.sin_addr.s_addr
        && server_peer.sin_port == client_local.sin_port;

    report!(
        tcp_connected_client_getpeername_rc = c_peer_rc,
        tcp_connected_client_getpeername_errno = errno_repr(c_peer_err),
        tcp_connected_server_getpeername_rc = s_peer_rc,
        tcp_connected_server_getpeername_errno = errno_repr(s_peer_err),
        tcp_client_peer_family_inet = client_peer_fam_inet,
        tcp_server_peer_family_inet = server_peer_fam_inet,
        tcp_client_peer_matches_server_local = client_peer_matches_server_local,
        tcp_server_peer_matches_client_local = server_peer_matches_client_local,
    );

    // 2.2 sendto with NULL destination on connected TCP
    let p_null = b"TCP_MSG_NULL_DEST";
    let rc_null = libc::sendto(
        client_fd,
        p_null.as_ptr() as *const libc::c_void,
        p_null.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        std::ptr::null(),
        0,
    );
    let err_null = if rc_null < 0 { errno() } else { 0 };
    let (_n_null, _err_recv_null, del_null) = bounded_recv_exact(server_fd, p_null, 500);

    report!(
        tcp_sendto_null_dest_rc = rc_null,
        tcp_sendto_null_dest_errno = errno_repr(err_null),
        tcp_sendto_null_dest_delivered = del_null,
    );

    // 2.3 sendto with NULL destination and positive length on connected TCP
    let p_null_len16 = b"TCP_MSG_NULL_LEN16";
    let rc_null_len16 = libc::sendto(
        client_fd,
        p_null_len16.as_ptr() as *const libc::c_void,
        p_null_len16.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        std::ptr::null(),
        16,
    );
    let err_null_len16 = if rc_null_len16 < 0 { errno() } else { 0 };
    let (_n_null_len16, _err_recv_null_len16, del_null_len16) =
        bounded_recv_exact(server_fd, p_null_len16, 500);

    report!(
        tcp_sendto_null_pos_len_rc = rc_null_len16,
        tcp_sendto_null_pos_len_errno = errno_repr(err_null_len16),
        tcp_sendto_null_pos_len_delivered = del_null_len16,
    );

    // 2.4 sendto with SUPPLIED matching peer destination on connected TCP
    let p_peer = b"TCP_MSG_PEER_DEST";
    let rc_peer = libc::sendto(
        client_fd,
        p_peer.as_ptr() as *const libc::c_void,
        p_peer.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &client_peer as *const _ as *const libc::sockaddr,
        size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    let err_peer = if rc_peer < 0 { errno() } else { 0 };
    let (_n_peer, _err_recv_peer, del_peer) = bounded_recv_exact(server_fd, p_peer, 500);

    report!(
        tcp_sendto_peer_dest_rc = rc_peer,
        tcp_sendto_peer_dest_errno = errno_repr(err_peer),
        tcp_sendto_peer_dest_delivered = del_peer,
    );

    // 2.5 sendto with SUPPLIED foreign destination (probe-owned loopback listener) on connected TCP
    // Linux ignores destination address on connected TCP streams and delivers to established peer.
    let p_diff = b"TCP_MSG_DIFF_DEST";
    let rc_diff = libc::sendto(
        client_fd,
        p_diff.as_ptr() as *const libc::c_void,
        p_diff.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &foreign_addr as *const _ as *const libc::sockaddr,
        size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    let err_diff = if rc_diff < 0 { errno() } else { 0 };
    let (_n_diff, _err_recv_diff, del_diff) = bounded_recv_exact(server_fd, p_diff, 500);

    report!(
        tcp_sendto_foreign_dest_rc = rc_diff,
        tcp_sendto_foreign_dest_errno = errno_repr(err_diff),
        tcp_sendto_foreign_dest_delivered = del_diff,
    );

    // 2.6 sendto with non-NULL destination and length 0 on connected TCP
    let p_len0 = b"TCP_MSG_LEN_ZERO";
    let rc_len0 = libc::sendto(
        client_fd,
        p_len0.as_ptr() as *const libc::c_void,
        p_len0.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &foreign_addr as *const _ as *const libc::sockaddr,
        0,
    );
    let err_len0 = if rc_len0 < 0 { errno() } else { 0 };
    let (_n_len0, _err_recv_len0, del_len0) = bounded_recv_exact(server_fd, p_len0, 500);

    report!(
        tcp_sendto_dest_len_zero_rc = rc_len0,
        tcp_sendto_dest_len_zero_errno = errno_repr(err_len0),
        tcp_sendto_dest_len_zero_delivered = del_len0,
    );

    // 2.7 sendto with non-NULL destination and short length 1 on connected TCP
    let p_short1 = b"TCP_MSG_SHORT_LEN1";
    let rc_short1 = libc::sendto(
        client_fd,
        p_short1.as_ptr() as *const libc::c_void,
        p_short1.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &foreign_addr as *const _ as *const libc::sockaddr,
        1,
    );
    let err_short1 = if rc_short1 < 0 { errno() } else { 0 };
    let (_n_short1, _err_recv_short1, del_short1) = bounded_recv_exact(server_fd, p_short1, 500);

    report!(
        tcp_sendto_short_len_rc = rc_short1,
        tcp_sendto_short_len_errno = errno_repr(err_short1),
        tcp_sendto_short_len_delivered = del_short1,
    );

    // 2.8 sendto with negative length on connected TCP -> EINVAL (from move_addr_to_kernel)
    let p_neg = b"TCP_MSG_NEG_LEN";
    let rc_neg = libc::sendto(
        client_fd,
        p_neg.as_ptr() as *const libc::c_void,
        p_neg.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &foreign_addr as *const _ as *const libc::sockaddr,
        (-1i32) as libc::socklen_t,
    );
    let err_neg = if rc_neg < 0 { errno() } else { 0 };
    let (_n_neg, _err_recv_neg, del_neg) = bounded_recv_exact(server_fd, p_neg, 50);

    report!(
        tcp_sendto_neg_len_rc = rc_neg,
        tcp_sendto_neg_len_errno = errno_repr(err_neg),
        tcp_sendto_neg_len_delivered = del_neg,
    );

    // 2.9 sendto with oversized length (> 128) on connected TCP -> EINVAL (from move_addr_to_kernel)
    let p_over = b"TCP_MSG_OVERSIZED_LEN";
    let rc_over = libc::sendto(
        client_fd,
        p_over.as_ptr() as *const libc::c_void,
        p_over.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &foreign_addr as *const _ as *const libc::sockaddr,
        129,
    );
    let err_over = if rc_over < 0 { errno() } else { 0 };
    let (_n_over, _err_recv_over, del_over) = bounded_recv_exact(server_fd, p_over, 50);

    report!(
        tcp_sendto_oversized_len_rc = rc_over,
        tcp_sendto_oversized_len_errno = errno_repr(err_over),
        tcp_sendto_oversized_len_delivered = del_over,
    );

    // 2.10 sendto with inaccessible pointer and positive length on connected TCP -> EFAULT
    let p_fault = b"TCP_MSG_EFAULT_PTR";
    let rc_fault = libc::sendto(
        client_fd,
        p_fault.as_ptr() as *const libc::c_void,
        p_fault.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        INACCESSIBLE_PTR,
        16,
    );
    let err_fault = if rc_fault < 0 { errno() } else { 0 };
    let (_n_fault, _err_recv_fault, del_fault) = bounded_recv_exact(server_fd, p_fault, 50);

    report!(
        tcp_sendto_inaccessible_pos_len_rc = rc_fault,
        tcp_sendto_inaccessible_pos_len_errno = errno_repr(err_fault),
        tcp_sendto_inaccessible_pos_len_delivered = del_fault,
    );

    // 2.11 sendto with inaccessible pointer and zero length on connected TCP
    // ulen == 0 skips copy_from_user in move_addr_to_kernel, so succeeds on Linux connected TCP!
    let p_inacc_zero = b"TCP_MSG_INACC_LEN0";
    let rc_inacc_zero = libc::sendto(
        client_fd,
        p_inacc_zero.as_ptr() as *const libc::c_void,
        p_inacc_zero.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        INACCESSIBLE_PTR,
        0,
    );
    let err_inacc_zero = if rc_inacc_zero < 0 { errno() } else { 0 };
    let (_n_inacc_zero, _err_recv_inacc_zero, del_inacc_zero) =
        bounded_recv_exact(server_fd, p_inacc_zero, 500);

    report!(
        tcp_sendto_inaccessible_zero_len_rc = rc_inacc_zero,
        tcp_sendto_inaccessible_zero_len_errno = errno_repr(err_inacc_zero),
        tcp_sendto_inaccessible_zero_len_delivered = del_inacc_zero,
    );

    // 2.12 sendto from server to client with supplied foreign destination
    let p_srv = b"TCP_MSG_SRV_TO_CLI";
    let rc_srv = libc::sendto(
        server_fd,
        p_srv.as_ptr() as *const libc::c_void,
        p_srv.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &foreign_addr as *const _ as *const libc::sockaddr,
        size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    let err_srv = if rc_srv < 0 { errno() } else { 0 };
    let (_n_srv, _err_recv_srv, del_srv) = bounded_recv_exact(client_fd, p_srv, 500);

    report!(
        tcp_sendto_server_to_client_rc = rc_srv,
        tcp_sendto_server_to_client_errno = errno_repr(err_srv),
        tcp_sendto_server_to_client_delivered = del_srv,
    );

    libc::close(server_fd);
    libc::close(client_fd);
    libc::close(foreign_listener);
    libc::close(listen_fd);
}

// -----------------------------------------------------------------------------
// 3. Adjacent UDP destination validation matrix
// -----------------------------------------------------------------------------

unsafe fn test_udp_destination_validation_matrix() {
    let udp_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0);
    if udp_fd < 0 {
        let err = errno();
        report!(udp_setup_ok = false, udp_setup_errno = errno_repr(err));
        return;
    }

    // Bind a probe-owned ephemeral loopback UDP receiver to verify valid datagram delivery
    let receiver_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0);
    if receiver_fd < 0 {
        let err = errno();
        libc::close(udp_fd);
        report!(udp_setup_ok = false, udp_setup_errno = errno_repr(err));
        return;
    }

    let mut bind_addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    bind_addr.sin_family = libc::AF_INET as libc::sa_family_t;
    bind_addr.sin_addr.s_addr = 0x7f000001u32.to_be(); // 127.0.0.1
    bind_addr.sin_port = 0; // ephemeral

    let b_rc = libc::bind(
        receiver_fd,
        &bind_addr as *const _ as *const libc::sockaddr,
        size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    if b_rc != 0 {
        let err = errno();
        libc::close(receiver_fd);
        libc::close(udp_fd);
        report!(udp_setup_ok = false, udp_setup_errno = errno_repr(err));
        return;
    }

    let mut valid_dest: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
    let mut valid_dest_len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let gs_rc = libc::getsockname(
        receiver_fd,
        &mut valid_dest as *mut _ as *mut libc::sockaddr,
        &mut valid_dest_len,
    );
    if gs_rc != 0 {
        let err = errno();
        libc::close(receiver_fd);
        libc::close(udp_fd);
        report!(udp_setup_ok = false, udp_setup_errno = errno_repr(err));
        return;
    }

    report!(udp_setup_ok = true, udp_setup_errno = errno_repr(0));

    let payload = b"UDP_TEST_PAYLOAD";

    // 3.1 UDP sendto with negative length -> EINVAL
    let rc_neg = libc::sendto(
        udp_fd,
        payload.as_ptr() as *const libc::c_void,
        payload.len(),
        libc::MSG_DONTWAIT,
        &valid_dest as *const _ as *const libc::sockaddr,
        (-1i32) as libc::socklen_t,
    );
    let err_neg = if rc_neg < 0 { errno() } else { 0 };

    // 3.2 UDP sendto with oversized length (> 128) -> EINVAL
    let rc_over = libc::sendto(
        udp_fd,
        payload.as_ptr() as *const libc::c_void,
        payload.len(),
        libc::MSG_DONTWAIT,
        &valid_dest as *const _ as *const libc::sockaddr,
        129,
    );
    let err_over = if rc_over < 0 { errno() } else { 0 };

    // 3.3 UDP sendto with zero length -> EINVAL
    let rc_len0 = libc::sendto(
        udp_fd,
        payload.as_ptr() as *const libc::c_void,
        payload.len(),
        libc::MSG_DONTWAIT,
        &valid_dest as *const _ as *const libc::sockaddr,
        0,
    );
    let err_len0 = if rc_len0 < 0 { errno() } else { 0 };

    // 3.4 UDP sendto with short length 1 -> EINVAL
    let rc_short1 = libc::sendto(
        udp_fd,
        payload.as_ptr() as *const libc::c_void,
        payload.len(),
        libc::MSG_DONTWAIT,
        &valid_dest as *const _ as *const libc::sockaddr,
        1,
    );
    let err_short1 = if rc_short1 < 0 { errno() } else { 0 };

    // 3.5 UDP sendto with inaccessible pointer and positive length -> EFAULT
    let rc_fault = libc::sendto(
        udp_fd,
        payload.as_ptr() as *const libc::c_void,
        payload.len(),
        libc::MSG_DONTWAIT,
        INACCESSIBLE_PTR,
        16,
    );
    let err_fault = if rc_fault < 0 { errno() } else { 0 };

    // 3.6 UDP sendto with inaccessible pointer and zero length -> EINVAL
    let rc_inacc_zero = libc::sendto(
        udp_fd,
        payload.as_ptr() as *const libc::c_void,
        payload.len(),
        libc::MSG_DONTWAIT,
        INACCESSIBLE_PTR,
        0,
    );
    let err_inacc_zero = if rc_inacc_zero < 0 { errno() } else { 0 };

    // 3.7 UDP sendto with valid destination -> success and verified delivery
    let rc_valid = libc::sendto(
        udp_fd,
        payload.as_ptr() as *const libc::c_void,
        payload.len(),
        libc::MSG_DONTWAIT,
        &valid_dest as *const _ as *const libc::sockaddr,
        size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    let err_valid = if rc_valid < 0 { errno() } else { 0 };
    let (_n_valid, _err_recv_valid, del_valid) = bounded_recv_exact(receiver_fd, payload, 500);

    report!(
        udp_sendto_neg_len_rc = rc_neg,
        udp_sendto_neg_len_errno = errno_repr(err_neg),
        udp_sendto_oversized_len_rc = rc_over,
        udp_sendto_oversized_len_errno = errno_repr(err_over),
        udp_sendto_zero_len_rc = rc_len0,
        udp_sendto_zero_len_errno = errno_repr(err_len0),
        udp_sendto_short1_len_rc = rc_short1,
        udp_sendto_short1_len_errno = errno_repr(err_short1),
        udp_sendto_inaccessible_pos_len_rc = rc_fault,
        udp_sendto_inaccessible_pos_len_errno = errno_repr(err_fault),
        udp_sendto_inaccessible_zero_len_rc = rc_inacc_zero,
        udp_sendto_inaccessible_zero_len_errno = errno_repr(err_inacc_zero),
        udp_sendto_valid_dest_rc = rc_valid,
        udp_sendto_valid_dest_errno = errno_repr(err_valid),
        udp_sendto_valid_dest_delivered = del_valid,
    );

    libc::close(receiver_fd);
    libc::close(udp_fd);
}

// -----------------------------------------------------------------------------
// 4. AF_UNIX socketpair getpeername & sendto matrix
// -----------------------------------------------------------------------------

unsafe fn test_unix_socketpair_matrix() {
    let mut sv = [-1i32; 2];
    let sp_rc = libc::socketpair(
        libc::AF_UNIX,
        libc::SOCK_STREAM | libc::SOCK_NONBLOCK,
        0,
        sv.as_mut_ptr(),
    );
    if sp_rc != 0 {
        let err = errno();
        report!(unix_setup_ok = false, unix_setup_errno = errno_repr(err));
        return;
    }

    report!(unix_setup_ok = true, unix_setup_errno = errno_repr(0));

    // 4.1 getpeername on connected AF_UNIX socketpair
    let mut sun0: libc::sockaddr_storage = MaybeUninit::zeroed().assume_init();
    let mut sun0_len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let gpn0_rc = libc::getpeername(
        sv[0],
        &mut sun0 as *mut _ as *mut libc::sockaddr,
        &mut sun0_len,
    );
    let gpn0_err = if gpn0_rc < 0 { errno() } else { 0 };

    let mut sun1: libc::sockaddr_storage = MaybeUninit::zeroed().assume_init();
    let mut sun1_len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let gpn1_rc = libc::getpeername(
        sv[1],
        &mut sun1 as *mut _ as *mut libc::sockaddr,
        &mut sun1_len,
    );
    let gpn1_err = if gpn1_rc < 0 { errno() } else { 0 };

    let peer0_fam_unix = gpn0_rc == 0 && (sun0.ss_family as i32 == libc::AF_UNIX);
    let peer1_fam_unix = gpn1_rc == 0 && (sun1.ss_family as i32 == libc::AF_UNIX);

    report!(
        unix_socketpair_peer0_getpeername_rc = gpn0_rc,
        unix_socketpair_peer0_getpeername_errno = errno_repr(gpn0_err),
        unix_socketpair_peer1_getpeername_rc = gpn1_rc,
        unix_socketpair_peer1_getpeername_errno = errno_repr(gpn1_err),
        unix_socketpair_peer0_family_unix = peer0_fam_unix,
        unix_socketpair_peer1_family_unix = peer1_fam_unix,
    );

    // 4.2 sendto with NULL destination on AF_UNIX stream socketpair
    let p_u_null = b"UNIX_MSG_NULL_DEST";
    let rc_u_null = libc::sendto(
        sv[0],
        p_u_null.as_ptr() as *const libc::c_void,
        p_u_null.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        std::ptr::null(),
        0,
    );
    let err_u_null = if rc_u_null < 0 { errno() } else { 0 };
    let (_n_u_null, _err_recv_u_null, del_u_null) = bounded_recv_exact(sv[1], p_u_null, 500);

    report!(
        unix_sendto_null_dest_rc = rc_u_null,
        unix_sendto_null_dest_errno = errno_repr(err_u_null),
        unix_sendto_null_dest_delivered = del_u_null,
    );

    // 4.3 sendto with SUPPLIED destination on AF_UNIX stream socketpair -> EISCONN on Linux
    let mut dest_sun: libc::sockaddr_un = MaybeUninit::zeroed().assume_init();
    dest_sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path = b"/tmp/streamdestmatrix_target.sock\0";
    for (i, &b) in path.iter().enumerate() {
        dest_sun.sun_path[i] = b as libc::c_char;
    }

    let p_u_dest = b"UNIX_MSG_SUPPLIED_DEST";
    let rc_u_dest = libc::sendto(
        sv[0],
        p_u_dest.as_ptr() as *const libc::c_void,
        p_u_dest.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &dest_sun as *const _ as *const libc::sockaddr,
        size_of::<libc::sockaddr_un>() as libc::socklen_t,
    );
    let err_u_dest = if rc_u_dest < 0 { errno() } else { 0 };

    // Verify sv[1] did not receive anything
    let mut pfd_u = libc::pollfd {
        fd: sv[1],
        events: libc::POLLIN,
        revents: 0,
    };
    let p_u = libc::poll(&mut pfd_u, 1, 50);
    let del_u_dest = if p_u > 0 {
        let mut tmp = [0u8; 64];
        let n = libc::recv(
            sv[1],
            tmp.as_mut_ptr() as *mut libc::c_void,
            tmp.len(),
            libc::MSG_DONTWAIT,
        );
        n > 0
    } else {
        false
    };

    report!(
        unix_sendto_supplied_dest_rc = rc_u_dest,
        unix_sendto_supplied_dest_errno = errno_repr(err_u_dest),
        unix_sendto_supplied_dest_delivered = del_u_dest,
    );

    // 4.4 sendto with destination length 0 on AF_UNIX stream socketpair
    // Linux treats namelen == 0 as no supplied destination, so delivers on established socketpair!
    let p_u_len0 = b"UNIX_MSG_LEN_ZERO";
    let rc_u_len0 = libc::sendto(
        sv[0],
        p_u_len0.as_ptr() as *const libc::c_void,
        p_u_len0.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &dest_sun as *const _ as *const libc::sockaddr,
        0,
    );
    let err_u_len0 = if rc_u_len0 < 0 { errno() } else { 0 };
    let (_n_u_len0, _err_recv_u_len0, del_u_len0) = bounded_recv_exact(sv[1], p_u_len0, 500);

    report!(
        unix_sendto_dest_len_zero_rc = rc_u_len0,
        unix_sendto_dest_len_zero_errno = errno_repr(err_u_len0),
        unix_sendto_dest_len_zero_delivered = del_u_len0,
    );

    // 4.5 sendto with negative length on AF_UNIX stream -> EINVAL
    let rc_u_neg = libc::sendto(
        sv[0],
        p_u_dest.as_ptr() as *const libc::c_void,
        p_u_dest.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &dest_sun as *const _ as *const libc::sockaddr,
        (-1i32) as libc::socklen_t,
    );
    let err_u_neg = if rc_u_neg < 0 { errno() } else { 0 };

    // 4.6 sendto with oversized length on AF_UNIX stream -> EINVAL
    let rc_u_over = libc::sendto(
        sv[0],
        p_u_dest.as_ptr() as *const libc::c_void,
        p_u_dest.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        &dest_sun as *const _ as *const libc::sockaddr,
        129,
    );
    let err_u_over = if rc_u_over < 0 { errno() } else { 0 };

    // 4.7 sendto with inaccessible pointer and positive length on AF_UNIX stream -> EFAULT
    let rc_u_fault = libc::sendto(
        sv[0],
        p_u_dest.as_ptr() as *const libc::c_void,
        p_u_dest.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        INACCESSIBLE_PTR,
        16,
    );
    let err_u_fault = if rc_u_fault < 0 { errno() } else { 0 };

    // 4.8 sendto with inaccessible pointer and zero length on AF_UNIX stream
    let p_u_inacc_zero = b"UNIX_MSG_INACC_LEN0";
    let rc_u_inacc_zero = libc::sendto(
        sv[0],
        p_u_inacc_zero.as_ptr() as *const libc::c_void,
        p_u_inacc_zero.len(),
        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        INACCESSIBLE_PTR,
        0,
    );
    let err_u_inacc_zero = if rc_u_inacc_zero < 0 { errno() } else { 0 };
    let (_n_u_inacc_zero, _err_recv_u_inacc_zero, del_u_inacc_zero) =
        bounded_recv_exact(sv[1], p_u_inacc_zero, 500);

    report!(
        unix_sendto_neg_len_rc = rc_u_neg,
        unix_sendto_neg_len_errno = errno_repr(err_u_neg),
        unix_sendto_oversized_len_rc = rc_u_over,
        unix_sendto_oversized_len_errno = errno_repr(err_u_over),
        unix_sendto_inaccessible_pos_len_rc = rc_u_fault,
        unix_sendto_inaccessible_pos_len_errno = errno_repr(err_u_fault),
        unix_sendto_inaccessible_zero_len_rc = rc_u_inacc_zero,
        unix_sendto_inaccessible_zero_len_errno = errno_repr(err_u_inacc_zero),
        unix_sendto_inaccessible_zero_len_delivered = del_u_inacc_zero,
    );

    libc::close(sv[0]);
    libc::close(sv[1]);
}

fn main() {
    unsafe {
        test_unconnected_getpeername();
        test_connected_inet_stream_matrix();
        test_udp_destination_validation_matrix();
        test_unix_socketpair_matrix();
    }
}
