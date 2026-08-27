//! Network flag, error, and cross-interface conformance matrix probe.
//!
//! Exercises Linux flag combinations, error returns, and interface interactions
//! across:
//! 1. Socket creation (socket / socketpair / accept4 with SOCK_NONBLOCK, SOCK_CLOEXEC,
//!    invalid flags, invalid families, and non-socket targets).
//! 2. Send and sendto flags (MSG_NOSIGNAL on closed peer, sendto with dest addr on
//!    connected stream -> EISCONN, sendto without dest addr on unconnected dgram ->
//!    EDESTADDRREQ, MSG_OOB on UDP -> EOPNOTSUPP, non-socket send -> ENOTSOCK).
//! 3. Recv and recvfrom flags (MSG_PEEK preserving queue, MSG_TRUNC returning full
//!    datagram length on SOCK_DGRAM, MSG_PEEK | MSG_DONTWAIT on empty socket -> EAGAIN,
//!    MSG_OOB on AF_UNIX -> EOPNOTSUPP / EINVAL, non-socket recv -> ENOTSOCK).
//! 4. Socket options (SO_ACCEPTCONN lifecycle across listen, SO_ERROR read-and-clear,
//!    read-only setsockopt rejections -> ENOPROTOOPT, invalid optnames -> ENOPROTOOPT,
//!    short optlen -> EINVAL, non-socket sockopt -> ENOTSOCK).
//! 5. Shutdown state transitions (invalid how -> EINVAL, unconnected shutdown -> ENOTCONN,
//!    SHUT_WR half-close with EPIPE / peer EOF / reverse communication, SHUT_RD EOF).
//! 6. Poll and Epoll matrix (POLLRDHUP, epoll_create1 flags, epoll_ctl error matrix,
//!    EPOLLRDHUP + EPOLLONESHOT disarm/rearm lifecycle, and MSG_PEEK poll/epoll coherence).
//!
//! Self-contained on AF_UNIX socketpairs and loopback sockets; deterministic boolean/key-value output only.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::mem::{size_of, MaybeUninit};

const POLLRDHUP: i16 = 0x2000;
const EPOLLRDHUP: u32 = 0x2000;
const EPOLLONESHOT: u32 = 1 << 30;

const SO_DOMAIN: libc::c_int = 39;
const SO_PROTOCOL: libc::c_int = 38;

unsafe fn create_temp_file(path: &str) -> i32 {
    let c = CString::new(path).unwrap();
    libc::open(
        c.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    )
}

unsafe fn unlink_file(path: &str) {
    let c = CString::new(path).unwrap();
    libc::unlink(c.as_ptr());
}

// -----------------------------------------------------------------------------
// 1. Socket, Socketpair, and Accept4 Creation Matrix
// -----------------------------------------------------------------------------

unsafe fn test_socket_creation_matrix() {
    // 1.1 socket() with combined SOCK_NONBLOCK | SOCK_CLOEXEC
    let s = libc::socket(
        libc::AF_UNIX,
        libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        0,
    );
    let s_ok = s >= 0;
    let (s_nonblock, s_cloexec) = if s_ok {
        let fl = libc::fcntl(s, libc::F_GETFL);
        let fd_fl = libc::fcntl(s, libc::F_GETFD);
        (
            (fl & libc::O_NONBLOCK) != 0,
            (fd_fl & libc::FD_CLOEXEC) != 0,
        )
    } else {
        (false, false)
    };
    if s >= 0 {
        libc::close(s);
    }

    // 1.2 socket() with invalid/unknown flag bits -> EINVAL
    let s_inv = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | 0x1000_0000, 0);
    let s_inv_errno = if s_inv < 0 { errno() } else { 0 };
    if s_inv >= 0 {
        libc::close(s_inv);
    }

    // 1.3 socket() with invalid domain/family -> EAFNOSUPPORT
    let s_bad_fam = libc::socket(9999, libc::SOCK_STREAM, 0);
    let s_bad_fam_errno = if s_bad_fam < 0 { errno() } else { 0 };
    if s_bad_fam >= 0 {
        libc::close(s_bad_fam);
    }

    // 1.4 socketpair() with SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC
    let mut sv = [-1i32; 2];
    let sp_rc = libc::socketpair(
        libc::AF_UNIX,
        libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        0,
        sv.as_mut_ptr(),
    );
    let sp_ok = sp_rc == 0;
    let (sp0_nb, sp0_clo, sp1_nb, sp1_clo) = if sp_ok {
        let fl0 = libc::fcntl(sv[0], libc::F_GETFL);
        let fd0 = libc::fcntl(sv[0], libc::F_GETFD);
        let fl1 = libc::fcntl(sv[1], libc::F_GETFL);
        let fd1 = libc::fcntl(sv[1], libc::F_GETFD);
        (
            (fl0 & libc::O_NONBLOCK) != 0,
            (fd0 & libc::FD_CLOEXEC) != 0,
            (fl1 & libc::O_NONBLOCK) != 0,
            (fd1 & libc::FD_CLOEXEC) != 0,
        )
    } else {
        (false, false, false, false)
    };
    if sv[0] >= 0 {
        libc::close(sv[0]);
    }
    if sv[1] >= 0 {
        libc::close(sv[1]);
    }

    // 1.5 socketpair() with unsupported family (AF_INET) -> EAFNOSUPPORT or EOPNOTSUPP
    let mut bad_sv = [-1i32; 2];
    let sp_bad = libc::socketpair(libc::AF_INET, libc::SOCK_STREAM, 0, bad_sv.as_mut_ptr());
    let sp_bad_errno = if sp_bad < 0 { errno() } else { 0 };
    if bad_sv[0] >= 0 {
        libc::close(bad_sv[0]);
    }
    if bad_sv[1] >= 0 {
        libc::close(bad_sv[1]);
    }

    // 1.6 accept4() with SOCK_NONBLOCK | SOCK_CLOEXEC and error paths
    let lfd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
    let sock_path = "/tmp/netflagmatrix_acc.sock";
    unlink_file(sock_path);
    let mut sun: libc::sockaddr_un = MaybeUninit::zeroed().assume_init();
    sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_bytes = sock_path.as_bytes();
    for (i, &b) in path_bytes.iter().enumerate() {
        sun.sun_path[i] = b as libc::c_char;
    }
    let sun_len = (size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;

    let bind_ok = libc::bind(lfd, &sun as *const _ as *const libc::sockaddr, sun_len) == 0;
    let listen_ok = libc::listen(lfd, 2) == 0;

    let cfd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
    let conn_ok = libc::connect(cfd, &sun as *const _ as *const libc::sockaddr, sun_len) == 0;

    // accept4 with invalid flags -> EINVAL
    let acc_inv = libc::accept4(lfd, std::ptr::null_mut(), std::ptr::null_mut(), 0x1234_5678);
    let acc_inv_errno = if acc_inv < 0 { errno() } else { 0 };
    if acc_inv >= 0 {
        libc::close(acc_inv);
    }

    // accept4 on non-socket fd -> ENOTSOCK
    let mut pipe_fds = [-1i32; 2];
    libc::pipe(pipe_fds.as_mut_ptr());
    let acc_pipe = libc::accept4(pipe_fds[0], std::ptr::null_mut(), std::ptr::null_mut(), 0);
    let acc_pipe_errno = if acc_pipe < 0 { errno() } else { 0 };
    libc::close(pipe_fds[0]);
    libc::close(pipe_fds[1]);

    // valid accept4 with SOCK_NONBLOCK | SOCK_CLOEXEC
    let afd = libc::accept4(
        lfd,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
    );
    let afd_ok = afd >= 0;
    let (afd_nonblock, afd_cloexec) = if afd_ok {
        let fl = libc::fcntl(afd, libc::F_GETFL);
        let fd_fl = libc::fcntl(afd, libc::F_GETFD);
        (
            (fl & libc::O_NONBLOCK) != 0,
            (fd_fl & libc::FD_CLOEXEC) != 0,
        )
    } else {
        (false, false)
    };

    if afd >= 0 {
        libc::close(afd);
    }
    if cfd >= 0 {
        libc::close(cfd);
    }
    if lfd >= 0 {
        libc::close(lfd);
    }
    unlink_file(sock_path);

    report!(
        sock_create_nonblock_cloexec = s_ok && s_nonblock && s_cloexec,
        sock_create_invalid_flags_einval = s_inv == -1 && s_inv_errno == libc::EINVAL,
        sock_create_invalid_family_eafnosupport =
            s_bad_fam == -1 && s_bad_fam_errno == libc::EAFNOSUPPORT,
        sockpair_dgram_nonblock_cloexec = sp_ok && sp0_nb && sp0_clo && sp1_nb && sp1_clo,
        sockpair_inet_eafnosupport = sp_bad == -1
            && (sp_bad_errno == libc::EAFNOSUPPORT || sp_bad_errno == libc::EOPNOTSUPP),
        accept4_setup_ok = bind_ok && listen_ok && conn_ok,
        accept4_invalid_flags_einval = acc_inv == -1 && acc_inv_errno == libc::EINVAL,
        accept4_not_socket_enotsock = acc_pipe == -1 && acc_pipe_errno == libc::ENOTSOCK,
        accept4_nonblock_cloexec = afd_ok && afd_nonblock && afd_cloexec,
    );
}

// -----------------------------------------------------------------------------
// 2. Send & Sendto Flag and Error Matrix
// -----------------------------------------------------------------------------

unsafe fn test_send_matrix() {
    let mut sv = [-1i32; 2];
    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());

    // 2.1 send with MSG_NOSIGNAL when peer is closed -> EPIPE (no SIGPIPE)
    libc::close(sv[1]);
    let buf = [0x55u8; 4];
    let send_nosig = libc::send(
        sv[0],
        buf.as_ptr() as *const libc::c_void,
        buf.len(),
        libc::MSG_NOSIGNAL,
    );
    let send_nosig_errno = if send_nosig < 0 { errno() } else { 0 };
    libc::close(sv[0]);

    // 2.2 sendto() on connected stream socket with non-NULL dest addr -> EISCONN
    let mut sv2 = [-1i32; 2];
    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv2.as_mut_ptr());
    let mut dest_addr: libc::sockaddr_un = MaybeUninit::zeroed().assume_init();
    dest_addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let sendto_isconn = libc::sendto(
        sv2[0],
        buf.as_ptr() as *const libc::c_void,
        buf.len(),
        0,
        &dest_addr as *const _ as *const libc::sockaddr,
        size_of::<libc::sockaddr_un>() as libc::socklen_t,
    );
    let sendto_isconn_errno = if sendto_isconn < 0 { errno() } else { 0 };
    libc::close(sv2[0]);
    libc::close(sv2[1]);

    // 2.3 MSG_OOB on UDP socket -> EOPNOTSUPP
    let dgram_fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    let send_oob = libc::send(
        dgram_fd,
        buf.as_ptr() as *const libc::c_void,
        buf.len(),
        libc::MSG_OOB,
    );
    let send_oob_errno = if send_oob < 0 { errno() } else { 0 };

    // 2.4 sendto() on unconnected SOCK_DGRAM with NULL dest addr -> EDESTADDRREQ
    let sendto_destreq = libc::sendto(
        dgram_fd,
        buf.as_ptr() as *const libc::c_void,
        buf.len(),
        0,
        std::ptr::null(),
        0,
    );
    let sendto_destreq_errno = if sendto_destreq < 0 { errno() } else { 0 };
    libc::close(dgram_fd);

    // 2.5 send() on non-socket fd -> ENOTSOCK
    let mut pipe_fds = [-1i32; 2];
    libc::pipe(pipe_fds.as_mut_ptr());
    let send_pipe = libc::send(
        pipe_fds[1],
        buf.as_ptr() as *const libc::c_void,
        buf.len(),
        0,
    );
    let send_pipe_errno = if send_pipe < 0 { errno() } else { 0 };
    libc::close(pipe_fds[0]);
    libc::close(pipe_fds[1]);

    report!(
        send_nosignal_closed_peer_epipe = send_nosig == -1 && send_nosig_errno == libc::EPIPE,
        sendto_connected_stream_dest_eisconn =
            sendto_isconn == -1 && sendto_isconn_errno == libc::EISCONN,
        send_oob_dgram_eopnotsupp = send_oob == -1 && send_oob_errno == libc::EOPNOTSUPP,
        sendto_dgram_unconnected_edestaddrreq =
            sendto_destreq == -1 && sendto_destreq_errno == libc::EDESTADDRREQ,
        send_not_socket_enotsock = send_pipe == -1 && send_pipe_errno == libc::ENOTSOCK,
    );
}

// -----------------------------------------------------------------------------
// 3. Recv & Recvfrom Flag and Error Matrix
// -----------------------------------------------------------------------------

unsafe fn test_recv_matrix() {
    let mut sv = [-1i32; 2];
    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());

    // 3.1 MSG_PEEK across multiple recvs on stream socket
    let msg = b"peekdata";
    libc::write(sv[0], msg.as_ptr() as *const libc::c_void, msg.len());

    let mut b1 = [0u8; 4];
    let r1 = libc::recv(
        sv[1],
        b1.as_mut_ptr() as *mut libc::c_void,
        b1.len(),
        libc::MSG_PEEK,
    );
    let peek1_ok = r1 == 4 && &b1 == b"peek";

    let mut b2 = [0u8; 4];
    let r2 = libc::recv(
        sv[1],
        b2.as_mut_ptr() as *mut libc::c_void,
        b2.len(),
        libc::MSG_PEEK,
    );
    let peek2_ok = r2 == 4 && &b2 == b"peek";

    let mut b3 = [0u8; 8];
    let r3 = libc::recv(sv[1], b3.as_mut_ptr() as *mut libc::c_void, b3.len(), 0);
    let consume_ok = r3 == 8 && &b3 == b"peekdata";

    let mut b4 = [0u8; 4];
    let r4 = libc::recv(
        sv[1],
        b4.as_mut_ptr() as *mut libc::c_void,
        b4.len(),
        libc::MSG_PEEK | libc::MSG_DONTWAIT,
    );
    let empty_eagain = r4 == -1 && errno() == libc::EAGAIN;

    // 3.2 MSG_OOB on AF_UNIX stream socket -> EOPNOTSUPP / EINVAL
    let r_oob = libc::recv(
        sv[1],
        b4.as_mut_ptr() as *mut libc::c_void,
        b4.len(),
        libc::MSG_OOB | libc::MSG_DONTWAIT,
    );
    let r_oob_errno = if r_oob < 0 { errno() } else { 0 };

    libc::close(sv[0]);
    libc::close(sv[1]);

    // 3.3 MSG_TRUNC in recv() on SOCK_DGRAM returns full packet length while truncating buffer
    let mut dsv = [-1i32; 2];
    libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, dsv.as_mut_ptr());
    let packet = [0xAAu8; 12];
    libc::send(
        dsv[0],
        packet.as_ptr() as *const libc::c_void,
        packet.len(),
        0,
    );

    let mut trunc_buf = [0u8; 4];
    let n_trunc = libc::recv(
        dsv[1],
        trunc_buf.as_mut_ptr() as *mut libc::c_void,
        trunc_buf.len(),
        libc::MSG_TRUNC | libc::MSG_DONTWAIT,
    );
    let trunc_ret_full_len = n_trunc == 12 && trunc_buf == [0xAA; 4];

    // Non-truncating recv consumes packet with length capped to buffer size
    libc::send(
        dsv[0],
        packet.as_ptr() as *const libc::c_void,
        packet.len(),
        0,
    );
    let mut notrunc_buf = [0u8; 4];
    let n_notrunc = libc::recv(
        dsv[1],
        notrunc_buf.as_mut_ptr() as *mut libc::c_void,
        notrunc_buf.len(),
        libc::MSG_DONTWAIT,
    );
    let notrunc_ret_buf_len = n_notrunc == 4 && notrunc_buf == [0xAA; 4];

    libc::close(dsv[0]);
    libc::close(dsv[1]);

    // 3.4 recv() on non-socket fd -> ENOTSOCK
    let mut pipe_fds = [-1i32; 2];
    libc::pipe(pipe_fds.as_mut_ptr());
    let r_pipe = libc::recv(
        pipe_fds[0],
        b4.as_mut_ptr() as *mut libc::c_void,
        b4.len(),
        libc::MSG_DONTWAIT,
    );
    let r_pipe_errno = if r_pipe < 0 { errno() } else { 0 };
    libc::close(pipe_fds[0]);
    libc::close(pipe_fds[1]);

    report!(
        recv_msg_peek_preserves_data = peek1_ok && peek2_ok && consume_ok && empty_eagain,
        recv_oob_af_unix_eopnotsupp =
            r_oob == -1 && (r_oob_errno == libc::EOPNOTSUPP || r_oob_errno == libc::EINVAL),
        recv_dgram_msg_trunc_returns_full_length = trunc_ret_full_len && notrunc_ret_buf_len,
        recv_not_socket_enotsock = r_pipe == -1 && r_pipe_errno == libc::ENOTSOCK,
    );
}

// -----------------------------------------------------------------------------
// 4. Sockopt Matrix & Error Coverage
// -----------------------------------------------------------------------------

unsafe fn test_sockopt_matrix() {
    let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);

    // 4.1 SO_ACCEPTCONN before and after listen()
    let mut acc_val: i32 = -1;
    let mut acc_len = size_of::<i32>() as libc::socklen_t;
    let g_acc1 = libc::getsockopt(
        s,
        libc::SOL_SOCKET,
        libc::SO_ACCEPTCONN,
        &mut acc_val as *mut _ as *mut libc::c_void,
        &mut acc_len,
    );
    let acc_before_listen = g_acc1 == 0 && acc_val == 0;

    let sock_path = "/tmp/netflagmatrix_opt.sock";
    unlink_file(sock_path);
    let mut sun: libc::sockaddr_un = MaybeUninit::zeroed().assume_init();
    sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_bytes = sock_path.as_bytes();
    for (i, &b) in path_bytes.iter().enumerate() {
        sun.sun_path[i] = b as libc::c_char;
    }
    let sun_len = (size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;
    libc::bind(s, &sun as *const _ as *const libc::sockaddr, sun_len);
    libc::listen(s, 1);

    acc_val = -1;
    acc_len = size_of::<i32>() as libc::socklen_t;
    let g_acc2 = libc::getsockopt(
        s,
        libc::SOL_SOCKET,
        libc::SO_ACCEPTCONN,
        &mut acc_val as *mut _ as *mut libc::c_void,
        &mut acc_len,
    );
    let acc_after_listen = g_acc2 == 0 && acc_val == 1;

    // 4.2 SO_ERROR read and clear semantics
    let mut err_val: i32 = -1;
    let mut err_len = size_of::<i32>() as libc::socklen_t;
    let g_err1 = libc::getsockopt(
        s,
        libc::SOL_SOCKET,
        libc::SO_ERROR,
        &mut err_val as *mut _ as *mut libc::c_void,
        &mut err_len,
    );
    let err_first_ok = g_err1 == 0 && err_val == 0;

    err_val = -1;
    err_len = size_of::<i32>() as libc::socklen_t;
    let g_err2 = libc::getsockopt(
        s,
        libc::SOL_SOCKET,
        libc::SO_ERROR,
        &mut err_val as *mut _ as *mut libc::c_void,
        &mut err_len,
    );
    let err_second_ok = g_err2 == 0 && err_val == 0;

    // 4.3 setsockopt on read-only options -> ENOPROTOOPT
    let val_one = 1i32;
    let val_len = size_of::<i32>() as libc::socklen_t;

    let s_type = libc::setsockopt(
        s,
        libc::SOL_SOCKET,
        libc::SO_TYPE,
        &val_one as *const _ as *const libc::c_void,
        val_len,
    );
    let s_type_enoprotoopt = s_type == -1 && errno() == libc::ENOPROTOOPT;

    let s_error = libc::setsockopt(
        s,
        libc::SOL_SOCKET,
        libc::SO_ERROR,
        &val_one as *const _ as *const libc::c_void,
        val_len,
    );
    let s_error_enoprotoopt = s_error == -1 && errno() == libc::ENOPROTOOPT;

    let s_acc = libc::setsockopt(
        s,
        libc::SOL_SOCKET,
        libc::SO_ACCEPTCONN,
        &val_one as *const _ as *const libc::c_void,
        val_len,
    );
    let s_acc_enoprotoopt = s_acc == -1 && errno() == libc::ENOPROTOOPT;

    let s_dom = libc::setsockopt(
        s,
        libc::SOL_SOCKET,
        SO_DOMAIN,
        &val_one as *const _ as *const libc::c_void,
        val_len,
    );
    let s_dom_enoprotoopt = s_dom == -1 && errno() == libc::ENOPROTOOPT;

    let s_proto = libc::setsockopt(
        s,
        libc::SOL_SOCKET,
        SO_PROTOCOL,
        &val_one as *const _ as *const libc::c_void,
        val_len,
    );
    let s_proto_enoprotoopt = s_proto == -1 && errno() == libc::ENOPROTOOPT;

    // 4.4 getsockopt and setsockopt with invalid optname -> ENOPROTOOPT
    let mut dummy = 0i32;
    let mut dummy_len = size_of::<i32>() as libc::socklen_t;
    let g_bad_opt = libc::getsockopt(
        s,
        libc::SOL_SOCKET,
        99999,
        &mut dummy as *mut _ as *mut libc::c_void,
        &mut dummy_len,
    );
    let g_bad_opt_enoprotoopt = g_bad_opt == -1 && errno() == libc::ENOPROTOOPT;

    let s_bad_opt = libc::setsockopt(
        s,
        libc::SOL_SOCKET,
        99999,
        &val_one as *const _ as *const libc::c_void,
        val_len,
    );
    let s_bad_opt_enoprotoopt = s_bad_opt == -1 && errno() == libc::ENOPROTOOPT;

    // 4.5 setsockopt with invalid length -> EINVAL
    let s_bad_len = libc::setsockopt(
        s,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        &val_one as *const _ as *const libc::c_void,
        1, // less than size_of::<i32>()
    );
    let s_bad_len_einval = s_bad_len == -1 && errno() == libc::EINVAL;

    // 4.6 sockopt on non-socket fd -> ENOTSOCK
    let mut pipe_fds = [-1i32; 2];
    libc::pipe(pipe_fds.as_mut_ptr());
    let g_pipe = libc::getsockopt(
        pipe_fds[0],
        libc::SOL_SOCKET,
        libc::SO_TYPE,
        &mut dummy as *mut _ as *mut libc::c_void,
        &mut dummy_len,
    );
    let g_pipe_enotsock = g_pipe == -1 && errno() == libc::ENOTSOCK;

    let s_pipe = libc::setsockopt(
        pipe_fds[0],
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        &val_one as *const _ as *const libc::c_void,
        val_len,
    );
    let s_pipe_enotsock = s_pipe == -1 && errno() == libc::ENOTSOCK;

    libc::close(pipe_fds[0]);
    libc::close(pipe_fds[1]);
    libc::close(s);
    unlink_file(sock_path);

    report!(
        sockopt_so_acceptconn_lifecycle = acc_before_listen && acc_after_listen,
        sockopt_so_error_read_and_clear = err_first_ok && err_second_ok,
        sockopt_readonly_setsockopt_enoprotoopt = s_type_enoprotoopt
            && s_error_enoprotoopt
            && s_acc_enoprotoopt
            && s_dom_enoprotoopt
            && s_proto_enoprotoopt,
        sockopt_invalid_optname_enoprotoopt = g_bad_opt_enoprotoopt && s_bad_opt_enoprotoopt,
        sockopt_short_optlen_einval = s_bad_len_einval,
        sockopt_not_socket_enotsock = g_pipe_enotsock && s_pipe_enotsock,
    );
}

// -----------------------------------------------------------------------------
// 5. Shutdown Flags and State Transitions
// -----------------------------------------------------------------------------

unsafe fn test_shutdown_matrix() {
    // 5.1 Invalid `how` argument -> EINVAL
    let mut sv = [-1i32; 2];
    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
    let shut_inv = libc::shutdown(sv[0], 99);
    let shut_inv_einval = shut_inv == -1 && errno() == libc::EINVAL;

    // 5.2 shutdown on unconnected AF_INET stream socket -> ENOTCONN
    let unconn_s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let shut_unconn = libc::shutdown(unconn_s, libc::SHUT_RDWR);
    let shut_unconn_enotconn = shut_unconn == -1 && errno() == libc::ENOTCONN;
    libc::close(unconn_s);

    // 5.3 shutdown on non-socket fd -> ENOTSOCK
    let mut pipe_fds = [-1i32; 2];
    libc::pipe(pipe_fds.as_mut_ptr());
    let shut_pipe = libc::shutdown(pipe_fds[0], libc::SHUT_RDWR);
    let shut_pipe_enotsock = shut_pipe == -1 && errno() == libc::ENOTSOCK;
    libc::close(pipe_fds[0]);
    libc::close(pipe_fds[1]);

    // 5.4 SHUT_WR state transitions: local send yields EPIPE, peer reads EOF (0), peer can still send
    let shut_wr_rc = libc::shutdown(sv[0], libc::SHUT_WR);
    let b = [0x33u8; 2];
    let send_after_shut_wr = libc::send(
        sv[0],
        b.as_ptr() as *const libc::c_void,
        b.len(),
        libc::MSG_NOSIGNAL,
    );
    let send_after_shut_wr_epipe = send_after_shut_wr == -1 && errno() == libc::EPIPE;

    let mut rcv = [0u8; 8];
    let read_eof = libc::read(sv[1], rcv.as_mut_ptr() as *mut libc::c_void, rcv.len());
    let peer_saw_eof = read_eof == 0;

    // Peer sending to shut_wr socket still works
    let send_rev = libc::send(sv[1], b.as_ptr() as *const libc::c_void, b.len(), 0);
    let mut rcv_rev = [0u8; 8];
    let read_rev = libc::read(
        sv[0],
        rcv_rev.as_mut_ptr() as *mut libc::c_void,
        rcv_rev.len(),
    );
    let reverse_comm_ok = send_rev == 2 && read_rev == 2 && &rcv_rev[..2] == &b;

    libc::close(sv[0]);
    libc::close(sv[1]);

    // 5.5 SHUT_RD state transitions: read returns 0 (EOF) immediately on empty socket
    let mut sv2 = [-1i32; 2];
    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv2.as_mut_ptr());
    let shut_rd_rc = libc::shutdown(sv2[0], libc::SHUT_RD);
    let mut rcv_rd = [0u8; 4];
    let read_after_shut_rd = libc::read(
        sv2[0],
        rcv_rd.as_mut_ptr() as *mut libc::c_void,
        rcv_rd.len(),
    );
    let shut_rd_eof = read_after_shut_rd == 0;

    libc::close(sv2[0]);
    libc::close(sv2[1]);

    report!(
        shutdown_invalid_how_einval = shut_inv_einval,
        shutdown_unconnected_enotconn = shut_unconn_enotconn,
        shutdown_not_socket_enotsock = shut_pipe_enotsock,
        shutdown_shut_wr_semantics =
            shut_wr_rc == 0 && send_after_shut_wr_epipe && peer_saw_eof && reverse_comm_ok,
        shutdown_shut_rd_eof = shut_rd_rc == 0 && shut_rd_eof,
    );
}

// -----------------------------------------------------------------------------
// 6. Poll & Epoll Flags, Error Matrix, and Cross-Interface State Matrix
// -----------------------------------------------------------------------------

unsafe fn test_poll_epoll_matrix() {
    // 6.1 POLLRDHUP on socketpair peer shutdown(SHUT_WR)
    let mut sv = [-1i32; 2];
    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr());
    libc::shutdown(sv[0], libc::SHUT_WR);

    let mut pfd = libc::pollfd {
        fd: sv[1],
        events: libc::POLLIN | POLLRDHUP,
        revents: 0,
    };
    let poll_rc = libc::poll(&mut pfd, 1, 50);
    let poll_rdhup_ok =
        poll_rc == 1 && (pfd.revents & libc::POLLIN) != 0 && (pfd.revents & POLLRDHUP) != 0;

    libc::close(sv[0]);
    libc::close(sv[1]);

    // 6.2 epoll_create1 flags: 0, EPOLL_CLOEXEC, invalid flags
    let ep0 = libc::epoll_create1(0);
    let ep0_ok = ep0 >= 0;
    let ep0_clo = if ep0_ok {
        (libc::fcntl(ep0, libc::F_GETFD) & libc::FD_CLOEXEC) != 0
    } else {
        false
    };
    if ep0 >= 0 {
        libc::close(ep0);
    }

    let ep_clo = libc::epoll_create1(libc::EPOLL_CLOEXEC);
    let ep_clo_ok = ep_clo >= 0;
    let ep_clo_flag = if ep_clo_ok {
        (libc::fcntl(ep_clo, libc::F_GETFD) & libc::FD_CLOEXEC) != 0
    } else {
        false
    };

    let ep_inv = libc::epoll_create1(0x1234_5678);
    let ep_inv_einval = ep_inv == -1 && errno() == libc::EINVAL;
    if ep_inv >= 0 {
        libc::close(ep_inv);
    }

    // 6.3 epoll_ctl error matrix
    let ep = ep_clo;
    let mut p = [-1i32; 2];
    libc::pipe(p.as_mut_ptr());
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: 100,
    };

    // Invalid op on valid target fd -> EINVAL
    let ctl_inv_op = libc::epoll_ctl(ep, 9999, p[0], &mut ev);
    let ctl_inv_op_einval = ctl_inv_op == -1 && errno() == libc::EINVAL;

    // epoll self-add -> EINVAL
    let ctl_self = libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, ep, &mut ev);
    let ctl_self_einval = ctl_self == -1 && errno() == libc::EINVAL;

    // epoll on regular file -> EPERM
    let temp_path = "/tmp/netflagmatrix_ep_file.tmp";
    let file_fd = create_temp_file(temp_path);
    let ctl_file = libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, file_fd, &mut ev);
    let ctl_file_eperm = ctl_file == -1 && errno() == libc::EPERM;
    libc::close(file_fd);
    unlink_file(temp_path);

    // DEL / MOD on fd not in epoll -> ENOENT
    let ctl_del_enoent = libc::epoll_ctl(ep, libc::EPOLL_CTL_DEL, p[0], &mut ev);
    let ctl_del_enoent_ok = ctl_del_enoent == -1 && errno() == libc::ENOENT;

    let ctl_mod_enoent = libc::epoll_ctl(ep, libc::EPOLL_CTL_MOD, p[0], &mut ev);
    let ctl_mod_enoent_ok = ctl_mod_enoent == -1 && errno() == libc::ENOENT;

    // Duplicate ADD -> EEXIST
    let ctl_add1 = libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, p[0], &mut ev);
    let ctl_add2 = libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, p[0], &mut ev);
    let ctl_dup_eexist = ctl_add1 == 0 && ctl_add2 == -1 && errno() == libc::EEXIST;

    // Invalid target fd -> EBADF
    let ctl_badf = libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, -1, &mut ev);
    let ctl_badf_ok = ctl_badf == -1 && errno() == libc::EBADF;

    // epoll_ctl on non-epoll fd -> EINVAL
    let ctl_non_epoll = libc::epoll_ctl(p[1], libc::EPOLL_CTL_ADD, p[0], &mut ev);
    let ctl_non_epoll_einval = ctl_non_epoll == -1 && errno() == libc::EINVAL;

    libc::close(p[0]);
    libc::close(p[1]);

    // 6.4 EPOLLRDHUP and EPOLLONESHOT lifecycle
    let mut sv2 = [-1i32; 2];
    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv2.as_mut_ptr());

    let mut oneshot_ev = libc::epoll_event {
        events: (libc::EPOLLIN as u32) | EPOLLRDHUP | EPOLLONESHOT,
        u64: sv2[1] as u64,
    };
    libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, sv2[1], &mut oneshot_ev);

    // Write data to sv2[0]
    let msg = b"oneshot";
    libc::write(sv2[0], msg.as_ptr() as *const libc::c_void, msg.len());

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];
    let n1 = libc::epoll_wait(ep, events.as_mut_ptr(), 2, 50);
    let wait1_in = n1 == 1 && (events[0].events & (libc::EPOLLIN as u32)) != 0;

    // Without reading, second wait with timeout=0 must yield 0 because ONESHOT disarmed it
    let n2 = libc::epoll_wait(ep, events.as_mut_ptr(), 2, 0);
    let wait2_disarmed = n2 == 0;

    // Shutdown peer write, rearm with EPOLL_CTL_MOD
    libc::shutdown(sv2[0], libc::SHUT_WR);
    let rearm_rc = libc::epoll_ctl(ep, libc::EPOLL_CTL_MOD, sv2[1], &mut oneshot_ev);
    let n3 = libc::epoll_wait(ep, events.as_mut_ptr(), 2, 50);
    let wait3_both = n3 == 1
        && (events[0].events & (libc::EPOLLIN as u32)) != 0
        && (events[0].events & EPOLLRDHUP) != 0;

    let mut buf = [0u8; 16];
    let drain_n = libc::read(sv2[1], buf.as_mut_ptr() as *mut libc::c_void, buf.len());
    let eof_n = libc::read(sv2[1], buf.as_mut_ptr() as *mut libc::c_void, buf.len());
    let oneshot_drain_ok = drain_n == msg.len() as isize && eof_n == 0;

    libc::close(sv2[0]);
    libc::close(sv2[1]);
    libc::close(ep);

    // 6.5 Cross-interface coherence: MSG_PEEK with poll and epoll
    let mut sv3 = [-1i32; 2];
    libc::socketpair(
        libc::AF_UNIX,
        libc::SOCK_STREAM | libc::SOCK_NONBLOCK,
        0,
        sv3.as_mut_ptr(),
    );
    let ep_peek = libc::epoll_create1(0);
    let mut peek_ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: sv3[1] as u64,
    };
    libc::epoll_ctl(ep_peek, libc::EPOLL_CTL_ADD, sv3[1], &mut peek_ev);

    libc::write(sv3[0], b"cohere".as_ptr() as *const libc::c_void, 6);

    let mut pfd_peek = libc::pollfd {
        fd: sv3[1],
        events: libc::POLLIN,
        revents: 0,
    };
    let p_before = libc::poll(&mut pfd_peek, 1, 50) == 1 && (pfd_peek.revents & libc::POLLIN) != 0;
    let mut ep_out = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let ep_before = libc::epoll_wait(ep_peek, ep_out.as_mut_ptr(), 1, 50) == 1
        && (ep_out[0].events & (libc::EPOLLIN as u32)) != 0;

    // MSG_PEEK read
    let mut peek_buf = [0u8; 6];
    let peek_rc = libc::recv(
        sv3[1],
        peek_buf.as_mut_ptr() as *mut libc::c_void,
        peek_buf.len(),
        libc::MSG_PEEK,
    );
    let peek_match = peek_rc == 6 && &peek_buf == b"cohere";

    // Poll and Epoll must STILL report POLLIN / EPOLLIN after MSG_PEEK
    pfd_peek.revents = 0;
    let p_mid = libc::poll(&mut pfd_peek, 1, 50) == 1 && (pfd_peek.revents & libc::POLLIN) != 0;
    let ep_mid = libc::epoll_wait(ep_peek, ep_out.as_mut_ptr(), 1, 50) == 1
        && (ep_out[0].events & (libc::EPOLLIN as u32)) != 0;

    // Full consuming read
    let consume_rc = libc::recv(
        sv3[1],
        peek_buf.as_mut_ptr() as *mut libc::c_void,
        peek_buf.len(),
        0,
    );
    let consume_match = consume_rc == 6 && &peek_buf == b"cohere";

    // Poll and Epoll with timeout 0 must now report no ready events
    pfd_peek.revents = 0;
    let p_after = libc::poll(&mut pfd_peek, 1, 0) == 0;
    let ep_after = libc::epoll_wait(ep_peek, ep_out.as_mut_ptr(), 1, 0) == 0;

    libc::close(sv3[0]);
    libc::close(sv3[1]);
    libc::close(ep_peek);

    report!(
        poll_rdhup_on_peer_shut_wr = poll_rdhup_ok,
        epoll_create1_flags_matrix =
            ep0_ok && !ep0_clo && ep_clo_ok && ep_clo_flag && ep_inv_einval,
        epoll_ctl_error_matrix = ctl_inv_op_einval
            && ctl_self_einval
            && ctl_file_eperm
            && ctl_del_enoent_ok
            && ctl_mod_enoent_ok
            && ctl_dup_eexist
            && ctl_badf_ok
            && ctl_non_epoll_einval,
        epoll_rdhup_and_oneshot_lifecycle =
            wait1_in && wait2_disarmed && rearm_rc == 0 && wait3_both && oneshot_drain_ok,
        cross_msg_peek_poll_epoll_coherence = p_before
            && ep_before
            && peek_match
            && p_mid
            && ep_mid
            && consume_match
            && p_after
            && ep_after,
    );
}

fn main() {
    unsafe {
        test_socket_creation_matrix();
        test_send_matrix();
        test_recv_matrix();
        test_sockopt_matrix();
        test_shutdown_matrix();
        test_poll_epoll_matrix();
    }
}
