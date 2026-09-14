//! Differential reducer for in-zone TCP graceful close, full close, and
//! listener-abort behavior. Every potentially blocking observation is gated by
//! a bounded poll; output contains raw return values and errno numbers.

use conformance_probes::{errno, report};

const POLL_MS: i32 = 500;

unsafe fn poll_read(fd: i32) -> (i32, i32, i16) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = libc::poll(&mut pfd, 1, POLL_MS);
    (rc, if rc < 0 { errno() } else { 0 }, pfd.revents)
}

unsafe fn poll_events(fd: i32, events: i16) -> (i32, i32, i16) {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let rc = libc::poll(&mut pfd, 1, POLL_MS);
    (rc, if rc < 0 { errno() } else { 0 }, pfd.revents)
}

unsafe fn listener() -> (i32, libc::sockaddr_in, libc::socklen_t, bool) {
    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    let mut addr: libc::sockaddr_in = std::mem::zeroed();
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
    if fd < 0
        || libc::bind(
            fd,
            &addr as *const _ as *const _,
            std::mem::size_of_val(&addr) as _,
        ) != 0
        || libc::listen(fd, 1) != 0
    {
        return (fd, addr, std::mem::size_of_val(&addr) as _, false);
    }
    let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
    let name_rc = libc::getsockname(fd, &mut addr as *mut _ as *mut _, &mut len);
    (
        fd,
        addr,
        len,
        name_rc == 0 && u16::from_be(addr.sin_port) != 0,
    )
}

unsafe fn connected_pair() -> (i32, i32) {
    let (listener_fd, addr, len, listener_ready) = listener();
    let client = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    let connect_rc = if client >= 0 {
        libc::connect(client, &addr as *const _ as *const _, len)
    } else {
        -1
    };
    let connect_errno = if connect_rc == 0 { 0 } else { errno() };
    let (poll_rc, _, _) = poll_events(client, libc::POLLOUT);
    let mut so_error = libc::EIO;
    let mut so_len = std::mem::size_of_val(&so_error) as libc::socklen_t;
    let connected = connect_rc == 0
        || (connect_errno == libc::EINPROGRESS
            && poll_rc > 0
            && libc::getsockopt(
                client,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut _ as *mut _,
                &mut so_len,
            ) == 0
            && so_error == 0);
    let (accept_poll, _, _) = poll_events(listener_fd, libc::POLLIN);
    if !listener_ready || listener_fd < 0 || client < 0 || !connected || accept_poll <= 0 {
        if listener_fd >= 0 {
            libc::close(listener_fd);
        }
        return (client, -1);
    }
    let server = libc::accept4(
        listener_fd,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        libc::SOCK_NONBLOCK,
    );
    libc::close(listener_fd);
    (client, server)
}

unsafe fn queued_client() -> (i32, i32, bool) {
    let (listener_fd, addr, len, listener_ready) = listener();
    let client = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
    let connect_rc = if client >= 0 && listener_ready {
        libc::connect(client, &addr as *const _ as *const _, len)
    } else {
        -1
    };
    let connect_errno = if connect_rc < 0 { errno() } else { 0 };
    let (poll_rc, _, _) = poll_events(client, libc::POLLOUT);
    let mut so_error = libc::EIO;
    let mut so_len = std::mem::size_of_val(&so_error) as libc::socklen_t;
    let connected = connect_rc == 0
        || (connect_errno == libc::EINPROGRESS
            && poll_rc > 0
            && libc::getsockopt(
                client,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut _ as *mut _,
                &mut so_len,
            ) == 0
            && so_error == 0);
    (listener_fd, client, connected)
}

unsafe fn close_if_open(fd: i32) -> bool {
    fd < 0 || libc::close(fd) == 0
}

unsafe fn recv_after_poll(fd: i32, buf: &mut [u8]) -> (bool, bool, isize, i32) {
    let (poll_rc, _, _) = poll_read(fd);
    if poll_rc == 0 {
        return (false, true, -1, 0);
    }
    if poll_rc < 0 {
        return (false, false, -1, errno());
    }
    let rc = libc::recv(
        fd,
        buf.as_mut_ptr() as *mut _,
        buf.len(),
        libc::MSG_DONTWAIT,
    );
    (true, false, rc, if rc < 0 { errno() } else { 0 })
}

unsafe fn socket_error(fd: i32) -> (i32, i32, i32) {
    let mut value = libc::EIO;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    let rc = libc::getsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_ERROR,
        &mut value as *mut _ as *mut _,
        &mut len,
    );
    (rc, if rc < 0 { errno() } else { 0 }, value)
}

fn main() {
    unsafe {
        // A: FIN after drained data; client must see EOF before its post-close write.
        let (client_a, server_a) = connected_pair();
        let a_write = if server_a >= 0 {
            libc::send(
                server_a,
                b"A".as_ptr() as *const _,
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let a_shutdown = if server_a >= 0 {
            libc::shutdown(server_a, libc::SHUT_WR)
        } else {
            -1
        };
        let (a_poll, a_poll_errno, a_revents) = poll_read(client_a);
        let mut a_buf = [0u8; 4];
        let (a_data_attempted, a_data_timeout, a_read_data, a_read_data_errno) =
            recv_after_poll(client_a, &mut a_buf[..1]);
        let (a_eof_attempted, a_eof_timeout, a_read_eof, a_read_eof_errno) =
            recv_after_poll(client_a, &mut a_buf[..1]);
        let a_write_after = if client_a >= 0 {
            libc::send(
                client_a,
                b"z".as_ptr() as *const _,
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let a_write_after_errno = if a_write_after < 0 { errno() } else { 0 };
        let (a_server_attempted, a_server_timeout, a_server_read, a_server_read_errno) =
            recv_after_poll(server_a, &mut a_buf[..1]);
        let a_client_closed = close_if_open(client_a);
        let a_server_closed = close_if_open(server_a);
        let a_cleanup = a_client_closed && a_server_closed;

        // B: full shutdown after unread data, then the same drain/EOF/write sequence.
        let (client_b, server_b) = connected_pair();
        let b_write = if server_b >= 0 {
            libc::send(
                server_b,
                b"BC".as_ptr() as *const _,
                2,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let b_shutdown = if server_b >= 0 {
            libc::shutdown(server_b, libc::SHUT_RDWR)
        } else {
            -1
        };
        let (b_poll, b_poll_errno, b_revents) = poll_read(client_b);
        let (b_data_attempted, b_data_timeout, b_read_data, b_read_data_errno) =
            recv_after_poll(client_b, &mut a_buf[..2]);
        let (b_drain_attempted, b_drain_timeout, b_read_after_drain, b_read_after_drain_errno) =
            recv_after_poll(client_b, &mut a_buf[..1]);
        let (b_write_poll, b_write_poll_errno, b_write_poll_revents) =
            poll_events(client_b, libc::POLLOUT);
        let b_write_after = if client_b >= 0 {
            libc::send(
                client_b,
                b"z".as_ptr() as *const _,
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let b_write_after_errno = if b_write_after < 0 { errno() } else { 0 };
        let (b_server_attempted, b_server_timeout, b_server_read, b_server_read_errno) =
            recv_after_poll(server_b, &mut a_buf[..1]);
        let (b_so_error_rc, b_so_error_errno, b_so_error) = socket_error(client_b);
        let b_write_second = if client_b >= 0 {
            libc::send(
                client_b,
                b"y".as_ptr() as *const _,
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let b_write_second_errno = if b_write_second < 0 { errno() } else { 0 };
        let (
            b_after_second_attempted,
            b_after_second_timeout,
            b_after_second_read,
            b_after_second_read_errno,
        ) = recv_after_poll(client_b, &mut a_buf[..1]);
        let (b_final_so_error_rc, b_final_so_error_errno, b_final_so_error) =
            socket_error(client_b);
        let b_client_closed = close_if_open(client_b);
        let b_server_closed = close_if_open(server_b);
        let b_cleanup = b_client_closed && b_server_closed;

        // C: dropping the peer after queued data must preserve the data, then EOF,
        // before the survivor attempts a write.
        let (client_c, server_c) = connected_pair();
        let c_write = if server_c >= 0 {
            libc::send(
                server_c,
                b"CD".as_ptr() as *const _,
                2,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let c_write_errno = if c_write < 0 { errno() } else { 0 };
        let c_server_close = if server_c >= 0 {
            libc::close(server_c)
        } else {
            -1
        };
        let c_server_close_errno = if c_server_close < 0 { errno() } else { 0 };
        let (c_data_attempted, c_data_timeout, c_read_data, c_read_data_errno) =
            recv_after_poll(client_c, &mut a_buf[..2]);
        let (c_eof_attempted, c_eof_timeout, c_read_eof, c_read_eof_errno) =
            recv_after_poll(client_c, &mut a_buf[..1]);
        let (c_write_poll, c_write_poll_errno, c_write_poll_revents) =
            poll_events(client_c, libc::POLLOUT);
        let c_write_after = if client_c >= 0 {
            libc::send(
                client_c,
                b"z".as_ptr() as *const _,
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let c_write_after_errno = if c_write_after < 0 { errno() } else { 0 };
        let (
            c_after_write_attempted,
            c_after_write_timeout,
            c_after_write_read,
            c_after_write_read_errno,
        ) = recv_after_poll(client_c, &mut a_buf[..1]);
        let (c_so_error_rc, c_so_error_errno, c_so_error) = socket_error(client_c);
        let c_write_second = if client_c >= 0 {
            libc::send(
                client_c,
                b"y".as_ptr() as *const _,
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let c_write_second_errno = if c_write_second < 0 { errno() } else { 0 };
        let (c_final_so_error_rc, c_final_so_error_errno, c_final_so_error) =
            socket_error(client_c);
        let c_cleanup = close_if_open(client_c);

        // D: close a listener while a completed connection is still queued and
        // observe the client-side reset without ever accepting the connection.
        let (listener_d, client_d, d_connected) = queued_client();
        let d_listener_close = if listener_d >= 0 {
            libc::close(listener_d)
        } else {
            -1
        };
        let d_listener_close_errno = if d_listener_close < 0 { errno() } else { 0 };
        let (d_read_attempted, d_read_timeout, d_read, d_read_errno) =
            recv_after_poll(client_d, &mut a_buf[..1]);
        let d_write = if client_d >= 0 {
            libc::send(
                client_d,
                b"z".as_ptr() as *const _,
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let d_write_errno = if d_write < 0 { errno() } else { 0 };
        let d_cleanup = close_if_open(client_d);

        // E: an accepted peer closed with SO_LINGER{1,0} sends an abortive RST.
        let (client_e, server_e) = connected_pair();
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let e_server_write = if server_e >= 0 {
            libc::send(
                server_e,
                b"EF".as_ptr() as *const _,
                2,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let e_server_write_errno = if e_server_write < 0 { errno() } else { 0 };
        let (e_preclose_poll, e_preclose_poll_errno, e_preclose_revents) = poll_read(client_e);
        let e_linger = if server_e >= 0 {
            libc::setsockopt(
                server_e,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const _ as *const _,
                std::mem::size_of_val(&linger) as _,
            )
        } else {
            -1
        };
        let e_linger_errno = if e_linger < 0 { errno() } else { 0 };
        let e_server_close = if server_e >= 0 {
            libc::close(server_e)
        } else {
            -1
        };
        let e_server_close_errno = if e_server_close < 0 { errno() } else { 0 };
        let (e_data_attempted, e_data_timeout, e_data_read, e_data_errno) =
            recv_after_poll(client_e, &mut a_buf[..2]);
        let (e_read_attempted, e_read_timeout, e_read, e_read_errno) =
            recv_after_poll(client_e, &mut a_buf[..1]);
        let e_write = if client_e >= 0 {
            libc::send(
                client_e,
                b"z".as_ptr() as *const _,
                1,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let e_write_errno = if e_write < 0 { errno() } else { 0 };
        let e_cleanup = close_if_open(client_e);

        // F: normal close with unread bytes queued at the closing endpoint.
        let (client_f, server_f) = connected_pair();
        let f_client_write = if client_f >= 0 {
            libc::send(
                client_f,
                b"FG".as_ptr() as *const _,
                2,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        } else {
            -1
        };
        let f_client_write_errno = if f_client_write < 0 { errno() } else { 0 };
        let (f_server_poll, f_server_poll_errno, f_server_revents) = poll_read(server_f);
        let f_server_close = if server_f >= 0 {
            libc::close(server_f)
        } else {
            -1
        };
        let f_server_close_errno = if f_server_close < 0 { errno() } else { 0 };
        let (f_read_attempted, f_read_timeout, f_read, f_read_errno) =
            recv_after_poll(client_f, &mut a_buf[..1]);
        let f_client_close = close_if_open(client_f);

        report!(
            fin_server_write_ret = a_write,
            fin_server_shutdown_ret = a_shutdown,
            fin_client_poll_ret = a_poll,
            fin_client_poll_errno = a_poll_errno,
            fin_client_poll_revents = a_revents,
            fin_client_read_data_attempted = a_data_attempted,
            fin_client_read_data_timeout = a_data_timeout,
            fin_client_read_data_ret = a_read_data,
            fin_client_read_data_errno = a_read_data_errno,
            fin_client_read_eof_attempted = a_eof_attempted,
            fin_client_read_eof_timeout = a_eof_timeout,
            fin_client_read_eof_ret = a_read_eof,
            fin_client_read_eof_errno = a_read_eof_errno,
            fin_client_write_after_eof_ret = a_write_after,
            fin_client_write_after_eof_errno = a_write_after_errno,
            fin_server_read_after_client_write_attempted = a_server_attempted,
            fin_server_read_after_client_write_timeout = a_server_timeout,
            fin_server_read_after_client_write_ret = a_server_read,
            fin_server_read_after_client_write_errno = a_server_read_errno,
            fin_cleanup_ok = a_cleanup,
            full_server_write_ret = b_write,
            full_server_shutdown_ret = b_shutdown,
            full_client_poll_ret = b_poll,
            full_client_poll_errno = b_poll_errno,
            full_client_poll_revents = b_revents,
            full_client_read_unread_data_attempted = b_data_attempted,
            full_client_read_unread_data_timeout = b_data_timeout,
            full_client_read_unread_data_ret = b_read_data,
            full_client_read_unread_data_errno = b_read_data_errno,
            full_client_read_after_drain_attempted = b_drain_attempted,
            full_client_read_after_drain_timeout = b_drain_timeout,
            full_client_read_after_drain_ret = b_read_after_drain,
            full_client_read_after_drain_errno = b_read_after_drain_errno,
            full_client_write_poll_ret = b_write_poll,
            full_client_write_poll_errno = b_write_poll_errno,
            full_client_write_poll_revents = b_write_poll_revents,
            full_client_write_after_drain_ret = b_write_after,
            full_client_write_after_drain_errno = b_write_after_errno,
            full_server_read_after_client_write_attempted = b_server_attempted,
            full_server_read_after_client_write_timeout = b_server_timeout,
            full_server_read_after_client_write_ret = b_server_read,
            full_server_read_after_client_write_errno = b_server_read_errno,
            full_client_so_error_ret = b_so_error_rc,
            full_client_so_error_errno = b_so_error_errno,
            full_client_so_error_value = b_so_error,
            full_client_second_write_ret = b_write_second,
            full_client_second_write_errno = b_write_second_errno,
            full_client_read_after_second_write_attempted = b_after_second_attempted,
            full_client_read_after_second_write_timeout = b_after_second_timeout,
            full_client_read_after_second_write_ret = b_after_second_read,
            full_client_read_after_second_write_errno = b_after_second_read_errno,
            full_client_final_so_error_ret = b_final_so_error_rc,
            full_client_final_so_error_errno = b_final_so_error_errno,
            full_client_final_so_error_value = b_final_so_error,
            full_cleanup_ok = b_cleanup,
            close_server_write_ret = c_write,
            close_server_write_errno = c_write_errno,
            close_server_close_ret = c_server_close,
            close_server_close_errno = c_server_close_errno,
            close_client_read_data_attempted = c_data_attempted,
            close_client_read_data_timeout = c_data_timeout,
            close_client_read_data_ret = c_read_data,
            close_client_read_data_errno = c_read_data_errno,
            close_client_read_eof_attempted = c_eof_attempted,
            close_client_read_eof_timeout = c_eof_timeout,
            close_client_read_eof_ret = c_read_eof,
            close_client_read_eof_errno = c_read_eof_errno,
            close_client_write_poll_ret = c_write_poll,
            close_client_write_poll_errno = c_write_poll_errno,
            close_client_write_poll_revents = c_write_poll_revents,
            close_client_write_after_eof_ret = c_write_after,
            close_client_write_after_eof_errno = c_write_after_errno,
            close_client_read_after_write_attempted = c_after_write_attempted,
            close_client_read_after_write_timeout = c_after_write_timeout,
            close_client_read_after_write_ret = c_after_write_read,
            close_client_read_after_write_errno = c_after_write_read_errno,
            close_client_so_error_ret = c_so_error_rc,
            close_client_so_error_errno = c_so_error_errno,
            close_client_so_error_value = c_so_error,
            close_client_second_write_ret = c_write_second,
            close_client_second_write_errno = c_write_second_errno,
            close_client_final_so_error_ret = c_final_so_error_rc,
            close_client_final_so_error_errno = c_final_so_error_errno,
            close_client_final_so_error_value = c_final_so_error,
            close_cleanup_ok = c_cleanup,
            queued_connected = d_connected,
            queued_listener_close_ret = d_listener_close,
            queued_listener_close_errno = d_listener_close_errno,
            queued_client_read_attempted = d_read_attempted,
            queued_client_read_timeout = d_read_timeout,
            queued_client_read_ret = d_read,
            queued_client_read_errno = d_read_errno,
            queued_client_write_ret = d_write,
            queued_client_write_errno = d_write_errno,
            queued_cleanup_ok = d_cleanup,
            reset_linger_ret = e_linger,
            reset_linger_errno = e_linger_errno,
            reset_server_write_ret = e_server_write,
            reset_server_write_errno = e_server_write_errno,
            reset_client_preclose_poll_ret = e_preclose_poll,
            reset_client_preclose_poll_errno = e_preclose_poll_errno,
            reset_client_preclose_poll_revents = e_preclose_revents,
            reset_server_close_ret = e_server_close,
            reset_server_close_errno = e_server_close_errno,
            reset_client_data_attempted = e_data_attempted,
            reset_client_data_timeout = e_data_timeout,
            reset_client_data_ret = e_data_read,
            reset_client_data_errno = e_data_errno,
            reset_client_read_attempted = e_read_attempted,
            reset_client_read_timeout = e_read_timeout,
            reset_client_read_ret = e_read,
            reset_client_read_errno = e_read_errno,
            reset_client_write_ret = e_write,
            reset_client_write_errno = e_write_errno,
            reset_cleanup_ok = e_cleanup,
            unread_client_write_ret = f_client_write,
            unread_client_write_errno = f_client_write_errno,
            unread_server_poll_ret = f_server_poll,
            unread_server_poll_errno = f_server_poll_errno,
            unread_server_poll_revents = f_server_revents,
            unread_server_close_ret = f_server_close,
            unread_server_close_errno = f_server_close_errno,
            unread_client_read_attempted = f_read_attempted,
            unread_client_read_timeout = f_read_timeout,
            unread_client_read_ret = f_read,
            unread_client_read_errno = f_read_errno,
            unread_cleanup_ok = f_client_close,
        );
    }
}
