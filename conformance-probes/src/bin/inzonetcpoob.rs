//! Conformance probe for in-zone TCP urgent-data boundaries.
//!
//! Mirrors libuv's `poll_oob` sequence: send `hello` with `MSG_OOB`, immediately
//! send normal `world`, then make a five-byte normal read before consuming the
//! urgent byte.  Linux stops that read at the urgent mark (`hell`), rather than
//! allowing it to consume the first byte of `world`.  The same observations are
//! repeated with `SO_OOBINLINE`, and every potentially blocking transition is
//! preceded by a bounded `poll`.

use conformance_probes::{errno, report};
use std::mem::MaybeUninit;

const WAIT_MS: libc::c_int = 1000;
const SIOCATMARK: usize = 0x8905;

#[derive(Clone, Copy)]
struct Call {
    attempted: bool,
    rc: i32,
    err: i32,
}

impl Call {
    const fn skipped() -> Self {
        Self {
            attempted: false,
            rc: 0,
            err: 0,
        }
    }

    fn observed(rc: i32) -> Self {
        Self {
            attempted: true,
            rc,
            err: if rc < 0 { errno() } else { 0 },
        }
    }
}

struct Case {
    setup: Call,
    connect: Call,
    connect_poll: Call,
    connect_so_error: Call,
    connect_so_error_value: i32,
    accept_poll: Call,
    accept: Call,
    set_inline: Call,
    send_oob: Call,
    send_normal: Call,
    ready_poll: Call,
    ready_revents: i16,
    mark_before: Call,
    mark_before_value: i32,
    normal_first: Call,
    normal_first_hex: String,
    mark_after_first: Call,
    mark_after_first_value: i32,
    recv_oob: Call,
    recv_oob_hex: String,
    mark_after_oob: Call,
    mark_after_oob_value: i32,
    second_ready_poll: Call,
    second_ready_revents: i16,
    normal_second: Call,
    normal_second_hex: String,
}

struct Pair {
    listener: i32,
    client: i32,
    server: i32,
}

impl Pair {
    unsafe fn close(self) {
        libc::close(self.server);
        libc::close(self.client);
        libc::close(self.listener);
    }
}

fn set_nonblock(fd: i32) -> Call {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Call::observed(flags);
        }
        Call::observed(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK))
    }
}

fn poll_one(fd: i32, events: i16) -> (Call, i16) {
    unsafe {
        let mut item = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let call = Call::observed(libc::poll(&mut item, 1, WAIT_MS));
        (call, item.revents)
    }
}

fn hex(bytes: &[u8], len: i32) -> String {
    if len <= 0 {
        return String::new();
    }
    bytes
        .iter()
        .take(len as usize)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn atmark(fd: i32) -> (Call, i32) {
    unsafe {
        let mut value = -1i32;
        // libc's ioctl request typedef is target-libc-specific; invoke the
        // Linux syscall shape directly so musl and glibc observe the same ABI.
        let call = Call::observed(
            libc::syscall(libc::SYS_ioctl, fd, SIOCATMARK, &mut value) as libc::c_int
        );
        (call, value)
    }
}

fn socket_error(fd: i32) -> (Call, i32) {
    unsafe {
        let mut value = -1i32;
        let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
        let call = Call::observed(libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        ));
        (call, value)
    }
}

/// Establish one fresh, entirely nonblocking loopback pair.  The detailed
/// connection observations remain in `run_case`; follow-up cases only need a
/// stable transport before isolating an OOB transition.
fn open_pair(inline: bool) -> Result<Pair, Call> {
    unsafe {
        let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let listener_open = Call::observed(listener);
        if listener < 0 {
            return Err(listener_open);
        }
        let client = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let client_open = Call::observed(client);
        if client < 0 {
            libc::close(listener);
            return Err(client_open);
        }
        let listener_nonblock = set_nonblock(listener);
        let client_nonblock = set_nonblock(client);
        if listener_nonblock.rc != 0 || client_nonblock.rc != 0 {
            libc::close(client);
            libc::close(listener);
            return Err(if listener_nonblock.rc != 0 {
                listener_nonblock
            } else {
                client_nonblock
            });
        }
        let mut addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let bind = Call::observed(libc::bind(
            listener,
            (&addr as *const libc::sockaddr_in).cast(),
            addr_len,
        ));
        let listen = if bind.rc == 0 {
            Call::observed(libc::listen(listener, 1))
        } else {
            Call::skipped()
        };
        if bind.rc != 0 || listen.rc != 0 {
            libc::close(client);
            libc::close(listener);
            return Err(if bind.rc != 0 { bind } else { listen });
        }
        let mut actual: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
        let mut actual_len = addr_len;
        let named = Call::observed(libc::getsockname(
            listener,
            (&mut actual as *mut libc::sockaddr_in).cast(),
            &mut actual_len,
        ));
        if named.rc != 0 {
            libc::close(client);
            libc::close(listener);
            return Err(named);
        }
        if inline {
            let value = 1i32;
            let set = Call::observed(libc::setsockopt(
                client,
                libc::SOL_SOCKET,
                libc::SO_OOBINLINE,
                (&value as *const i32).cast(),
                std::mem::size_of_val(&value) as libc::socklen_t,
            ));
            if set.rc != 0 {
                libc::close(client);
                libc::close(listener);
                return Err(set);
            }
        }
        let connected = Call::observed(libc::connect(
            client,
            (&actual as *const libc::sockaddr_in).cast(),
            actual_len,
        ));
        if connected.rc < 0 && connected.err != libc::EINPROGRESS {
            libc::close(client);
            libc::close(listener);
            return Err(connected);
        }
        let (connect_poll, _) = poll_one(client, libc::POLLOUT);
        let (so_error_call, so_error) = socket_error(client);
        let (accept_poll, _) = poll_one(listener, libc::POLLIN);
        if connect_poll.rc <= 0 || so_error_call.rc != 0 || so_error != 0 || accept_poll.rc <= 0 {
            libc::close(client);
            libc::close(listener);
            return Err(if connect_poll.rc <= 0 {
                connect_poll
            } else if so_error_call.rc != 0 {
                so_error_call
            } else if so_error != 0 {
                Call {
                    attempted: true,
                    rc: -1,
                    err: so_error,
                }
            } else {
                accept_poll
            });
        }
        let server = libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_NONBLOCK,
        );
        if server < 0 {
            let error = Call::observed(server);
            libc::close(client);
            libc::close(listener);
            return Err(error);
        }
        Ok(Pair {
            listener,
            client,
            server,
        })
    }
}

fn recv_hex(fd: i32, flags: i32) -> (Call, String) {
    recv_len_hex(fd, 16, flags)
}

fn recv_len_hex(fd: i32, len: usize, flags: i32) -> (Call, String) {
    unsafe {
        let mut buf = [0u8; 16];
        let call = Call::observed(libc::recv(
            fd,
            buf.as_mut_ptr().cast(),
            len.min(buf.len()),
            flags | libc::MSG_DONTWAIT,
        ) as i32);
        let bytes = hex(&buf, call.rc);
        (call, bytes)
    }
}

fn send_bytes(fd: i32, data: &[u8], flags: i32) -> Call {
    unsafe {
        Call::observed(libc::send(
            fd,
            data.as_ptr().cast(),
            data.len(),
            flags | libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        ) as i32)
    }
}

fn run_case(inline: bool) -> Case {
    let mut result = Case {
        setup: Call::skipped(),
        connect: Call::skipped(),
        connect_poll: Call::skipped(),
        connect_so_error: Call::skipped(),
        connect_so_error_value: -1,
        accept_poll: Call::skipped(),
        accept: Call::skipped(),
        set_inline: Call::skipped(),
        send_oob: Call::skipped(),
        send_normal: Call::skipped(),
        ready_poll: Call::skipped(),
        ready_revents: 0,
        mark_before: Call::skipped(),
        mark_before_value: -1,
        normal_first: Call::skipped(),
        normal_first_hex: String::new(),
        mark_after_first: Call::skipped(),
        mark_after_first_value: -1,
        recv_oob: Call::skipped(),
        recv_oob_hex: String::new(),
        mark_after_oob: Call::skipped(),
        mark_after_oob_value: -1,
        second_ready_poll: Call::skipped(),
        second_ready_revents: 0,
        normal_second: Call::skipped(),
        normal_second_hex: String::new(),
    };
    unsafe {
        let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let listener_open = Call::observed(listener);
        let client = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let client_open = Call::observed(client);
        if listener < 0 || client < 0 {
            result.setup = if listener < 0 {
                listener_open
            } else {
                client_open
            };
            if listener >= 0 {
                libc::close(listener);
            }
            if client >= 0 {
                libc::close(client);
            }
            return result;
        }

        let mut addr: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        let addr_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let listener_nonblock = set_nonblock(listener);
        let client_nonblock = set_nonblock(client);
        let bind_rc = libc::bind(
            listener,
            (&addr as *const libc::sockaddr_in).cast(),
            addr_len,
        );
        let listen_rc = if bind_rc == 0 {
            libc::listen(listener, 1)
        } else {
            -1
        };
        if listener_nonblock.rc != 0 {
            result.setup = listener_nonblock;
            libc::close(client);
            libc::close(listener);
            return result;
        }
        if client_nonblock.rc != 0 {
            result.setup = client_nonblock;
            libc::close(client);
            libc::close(listener);
            return result;
        }
        if bind_rc != 0 || listen_rc != 0 {
            result.setup = Call::observed(if bind_rc != 0 { bind_rc } else { listen_rc });
            libc::close(client);
            libc::close(listener);
            return result;
        }
        let mut actual: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
        let mut actual_len = addr_len;
        let named = libc::getsockname(
            listener,
            (&mut actual as *mut libc::sockaddr_in).cast(),
            &mut actual_len,
        );
        result.setup = Call::observed(named);
        if named != 0 {
            libc::close(client);
            libc::close(listener);
            return result;
        }

        if inline {
            let enabled: libc::c_int = 1;
            result.set_inline = Call::observed(libc::setsockopt(
                client,
                libc::SOL_SOCKET,
                libc::SO_OOBINLINE,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            ));
            if result.set_inline.rc != 0 {
                libc::close(client);
                libc::close(listener);
                return result;
            }
        }
        result.connect = Call::observed(libc::connect(
            client,
            (&actual as *const libc::sockaddr_in).cast(),
            actual_len,
        ));
        if result.connect.rc < 0 && result.connect.err != libc::EINPROGRESS {
            libc::close(client);
            libc::close(listener);
            return result;
        }
        let (connect_poll, _) = poll_one(client, libc::POLLOUT);
        result.connect_poll = connect_poll;
        (result.connect_so_error, result.connect_so_error_value) = socket_error(client);
        let (accept_poll, _) = poll_one(listener, libc::POLLIN);
        result.accept_poll = accept_poll;
        if connect_poll.rc <= 0 || accept_poll.rc <= 0 {
            libc::close(client);
            libc::close(listener);
            return result;
        }
        let server = libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_NONBLOCK,
        );
        result.accept = if server < 0 {
            Call::observed(server)
        } else {
            // The descriptor number is allocator-dependent and has no ABI meaning.
            Call {
                attempted: true,
                rc: 0,
                err: 0,
            }
        };
        if server < 0 {
            libc::close(client);
            libc::close(listener);
            return result;
        }

        result.send_oob = Call::observed(libc::send(
            server,
            b"hello".as_ptr().cast(),
            5,
            libc::MSG_OOB | libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        ) as i32);
        result.send_normal = Call::observed(libc::send(
            server,
            b"world".as_ptr().cast(),
            5,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        ) as i32);
        let (ready_poll, revents) = poll_one(client, libc::POLLIN | libc::POLLPRI);
        result.ready_poll = ready_poll;
        result.ready_revents = revents;

        (result.mark_before, result.mark_before_value) = atmark(client);
        let mut first = [0u8; 5];
        result.normal_first = Call::observed(libc::recv(
            client,
            first.as_mut_ptr().cast(),
            first.len(),
            libc::MSG_DONTWAIT,
        ) as i32);
        result.normal_first_hex = hex(&first, result.normal_first.rc);
        (result.mark_after_first, result.mark_after_first_value) = atmark(client);
        let mut oob = [0u8; 5];
        result.recv_oob = Call::observed(libc::recv(
            client,
            oob.as_mut_ptr().cast(),
            oob.len(),
            libc::MSG_OOB | libc::MSG_DONTWAIT,
        ) as i32);
        result.recv_oob_hex = hex(&oob, result.recv_oob.rc);
        (result.mark_after_oob, result.mark_after_oob_value) = atmark(client);
        let (second_ready_poll, second_ready_revents) = poll_one(client, libc::POLLIN);
        result.second_ready_poll = second_ready_poll;
        result.second_ready_revents = second_ready_revents;
        let mut second = [0u8; 5];
        result.normal_second = Call::observed(libc::recv(
            client,
            second.as_mut_ptr().cast(),
            second.len(),
            libc::MSG_DONTWAIT,
        ) as i32);
        result.normal_second_hex = hex(&second, result.normal_second.rc);

        libc::close(server);
        libc::close(client);
        libc::close(listener);
    }
    result
}

fn emit_setup_error(case: &str, error: Call) {
    report!(
        oob_case = case,
        setup_attempted = error.attempted,
        setup_rc = error.rc,
        setup_errno = error.err,
    );
}

/// Does a normal read at a separate urgent mark cross into ordinary suffix
/// data before userspace consumes MSG_OOB?
fn run_cross_mark_case() {
    let pair = match open_pair(false) {
        Ok(pair) => pair,
        Err(error) => return emit_setup_error("cross_mark", error),
    };
    let oob = send_bytes(pair.server, b"hello", libc::MSG_OOB);
    let normal = send_bytes(pair.server, b"world", 0);
    let (ready, ready_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (first, first_hex) = recv_hex(pair.client, 0);
    let (mark, mark_value) = atmark(pair.client);
    let (at_mark_poll, at_mark_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (across, across_hex) = recv_hex(pair.client, 0);
    let (after_across_mark, after_across_mark_value) = atmark(pair.client);
    let (before_oob_poll, before_oob_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (oob_read, oob_hex) = recv_hex(pair.client, libc::MSG_OOB);
    let (after_oob_poll, after_oob_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (tail, tail_hex) = recv_hex(pair.client, 0);
    unsafe { pair.close() };
    report!(
        oob_case = "cross_mark",
        setup_rc = 0,
        send_oob_rc = oob.rc,
        send_oob_errno = oob.err,
        send_normal_rc = normal.rc,
        send_normal_errno = normal.err,
        ready_poll_rc = ready.rc,
        ready_poll_errno = ready.err,
        ready_poll_revents = ready_events,
        first_rc = first.rc,
        first_errno = first.err,
        first_hex = first_hex,
        mark_rc = mark.rc,
        mark_errno = mark.err,
        mark_value = mark_value,
        at_mark_poll_rc = at_mark_poll.rc,
        at_mark_poll_errno = at_mark_poll.err,
        at_mark_poll_revents = at_mark_events,
        across_rc = across.rc,
        across_errno = across.err,
        across_hex = across_hex,
        after_across_mark_rc = after_across_mark.rc,
        after_across_mark_errno = after_across_mark.err,
        after_across_mark_value = after_across_mark_value,
        before_oob_poll_rc = before_oob_poll.rc,
        before_oob_poll_errno = before_oob_poll.err,
        before_oob_poll_revents = before_oob_events,
        oob_read_rc = oob_read.rc,
        oob_read_errno = oob_read.err,
        oob_read_hex = oob_hex,
        after_oob_poll_rc = after_oob_poll.rc,
        after_oob_poll_errno = after_oob_poll.err,
        after_oob_poll_revents = after_oob_events,
        tail_rc = tail.rc,
        tail_errno = tail.err,
        tail_hex = tail_hex,
    );
}

/// PEEK must neither advance the normal cursor nor consume the urgent byte.
fn run_peek_case() {
    let pair = match open_pair(false) {
        Ok(pair) => pair,
        Err(error) => return emit_setup_error("peek", error),
    };
    let oob = send_bytes(pair.server, b"hello", libc::MSG_OOB);
    let normal = send_bytes(pair.server, b"world", 0);
    let (ready, ready_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (normal_peek, normal_peek_hex) = recv_hex(pair.client, libc::MSG_PEEK);
    let (after_normal_peek_mark, after_normal_peek_mark_value) = atmark(pair.client);
    let (normal_read, normal_read_hex) = recv_hex(pair.client, 0);
    let (at_mark_poll, at_mark_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (normal_at_mark_peek, normal_at_mark_peek_hex) = recv_hex(pair.client, libc::MSG_PEEK);
    let (after_normal_at_mark_peek_poll, after_normal_at_mark_peek_events) =
        poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (oob_peek, oob_peek_hex) = recv_hex(pair.client, libc::MSG_OOB | libc::MSG_PEEK);
    let (after_oob_peek_poll, after_oob_peek_events) =
        poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (oob_read, oob_read_hex) = recv_hex(pair.client, libc::MSG_OOB);
    let (tail_poll, tail_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (tail, tail_hex) = recv_hex(pair.client, 0);
    unsafe { pair.close() };
    report!(
        oob_case = "peek",
        setup_rc = 0,
        send_oob_rc = oob.rc,
        send_oob_errno = oob.err,
        send_normal_rc = normal.rc,
        send_normal_errno = normal.err,
        ready_poll_rc = ready.rc,
        ready_poll_errno = ready.err,
        ready_poll_revents = ready_events,
        normal_peek_rc = normal_peek.rc,
        normal_peek_errno = normal_peek.err,
        normal_peek_hex = normal_peek_hex,
        after_normal_peek_mark_rc = after_normal_peek_mark.rc,
        after_normal_peek_mark_errno = after_normal_peek_mark.err,
        after_normal_peek_mark_value = after_normal_peek_mark_value,
        normal_read_rc = normal_read.rc,
        normal_read_errno = normal_read.err,
        normal_read_hex = normal_read_hex,
        at_mark_poll_rc = at_mark_poll.rc,
        at_mark_poll_errno = at_mark_poll.err,
        at_mark_poll_revents = at_mark_events,
        normal_at_mark_peek_rc = normal_at_mark_peek.rc,
        normal_at_mark_peek_errno = normal_at_mark_peek.err,
        normal_at_mark_peek_hex = normal_at_mark_peek_hex,
        after_normal_at_mark_peek_poll_rc = after_normal_at_mark_peek_poll.rc,
        after_normal_at_mark_peek_poll_errno = after_normal_at_mark_peek_poll.err,
        after_normal_at_mark_peek_poll_revents = after_normal_at_mark_peek_events,
        oob_peek_rc = oob_peek.rc,
        oob_peek_errno = oob_peek.err,
        oob_peek_hex = oob_peek_hex,
        after_oob_peek_poll_rc = after_oob_peek_poll.rc,
        after_oob_peek_poll_errno = after_oob_peek_poll.err,
        after_oob_peek_poll_revents = after_oob_peek_events,
        oob_read_rc = oob_read.rc,
        oob_read_errno = oob_read.err,
        oob_read_hex = oob_read_hex,
        tail_poll_rc = tail_poll.rc,
        tail_poll_errno = tail_poll.err,
        tail_poll_revents = tail_events,
        tail_rc = tail.rc,
        tail_errno = tail.err,
        tail_hex = tail_hex,
    );
}

/// Successive urgent sends reveal whether Linux supersedes or queues the
/// earlier urgent byte, without relying on any local queueing policy.
fn run_repeated_case() {
    let pair = match open_pair(false) {
        Ok(pair) => pair,
        Err(error) => return emit_setup_error("repeated", error),
    };
    let first_send = send_bytes(pair.server, b"one!", libc::MSG_OOB);
    let second_send = send_bytes(pair.server, b"two?", libc::MSG_OOB);
    let suffix_send = send_bytes(pair.server, b"tail", 0);
    let (ready, ready_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (first_normal, first_normal_hex) = recv_hex(pair.client, 0);
    let (mark, mark_value) = atmark(pair.client);
    let (mark_poll, mark_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (first_oob, first_oob_hex) = recv_hex(pair.client, libc::MSG_OOB);
    let (after_first_oob_poll, after_first_oob_events) =
        poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (second_oob, second_oob_hex) = recv_hex(pair.client, libc::MSG_OOB);
    let (tail_poll, tail_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (tail, tail_hex) = recv_hex(pair.client, 0);
    unsafe { pair.close() };
    report!(
        oob_case = "repeated",
        setup_rc = 0,
        first_send_rc = first_send.rc,
        first_send_errno = first_send.err,
        second_send_rc = second_send.rc,
        second_send_errno = second_send.err,
        suffix_send_rc = suffix_send.rc,
        suffix_send_errno = suffix_send.err,
        ready_poll_rc = ready.rc,
        ready_poll_errno = ready.err,
        ready_poll_revents = ready_events,
        first_normal_rc = first_normal.rc,
        first_normal_errno = first_normal.err,
        first_normal_hex = first_normal_hex,
        mark_rc = mark.rc,
        mark_errno = mark.err,
        mark_value = mark_value,
        mark_poll_rc = mark_poll.rc,
        mark_poll_errno = mark_poll.err,
        mark_poll_revents = mark_events,
        first_oob_rc = first_oob.rc,
        first_oob_errno = first_oob.err,
        first_oob_hex = first_oob_hex,
        after_first_oob_poll_rc = after_first_oob_poll.rc,
        after_first_oob_poll_errno = after_first_oob_poll.err,
        after_first_oob_poll_revents = after_first_oob_events,
        second_oob_rc = second_oob.rc,
        second_oob_errno = second_oob.err,
        second_oob_hex = second_oob_hex,
        tail_poll_rc = tail_poll.rc,
        tail_poll_errno = tail_poll.err,
        tail_poll_revents = tail_events,
        tail_rc = tail.rc,
        tail_errno = tail.err,
        tail_hex = tail_hex,
    );
}

/// Toggle OOBINLINE only after the urgent indication arrived, so the oracle
/// identifies whether delivery mode is fixed at arrival or read time.
fn run_toggle_after_arrival_case() {
    let pair = match open_pair(false) {
        Ok(pair) => pair,
        Err(error) => return emit_setup_error("toggle_after_arrival", error),
    };
    let oob = send_bytes(pair.server, b"hello", libc::MSG_OOB);
    let normal = send_bytes(pair.server, b"world", 0);
    let (ready, ready_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let enabled = 1i32;
    let toggle = unsafe {
        Call::observed(libc::setsockopt(
            pair.client,
            libc::SOL_SOCKET,
            libc::SO_OOBINLINE,
            (&enabled as *const i32).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        ))
    };
    let (first, first_hex) = recv_hex(pair.client, 0);
    let (mark, mark_value) = atmark(pair.client);
    let (before_oob_poll, before_oob_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (oob_read, oob_hex) = recv_hex(pair.client, libc::MSG_OOB);
    let (priority_poll, priority_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (tail, tail_hex) = recv_hex(pair.client, 0);
    unsafe { pair.close() };
    report!(
        oob_case = "toggle_after_arrival",
        setup_rc = 0,
        send_oob_rc = oob.rc,
        send_oob_errno = oob.err,
        send_normal_rc = normal.rc,
        send_normal_errno = normal.err,
        ready_poll_rc = ready.rc,
        ready_poll_errno = ready.err,
        ready_poll_revents = ready_events,
        toggle_rc = toggle.rc,
        toggle_errno = toggle.err,
        first_rc = first.rc,
        first_errno = first.err,
        first_hex = first_hex,
        mark_rc = mark.rc,
        mark_errno = mark.err,
        mark_value = mark_value,
        before_oob_poll_rc = before_oob_poll.rc,
        before_oob_poll_errno = before_oob_poll.err,
        before_oob_poll_revents = before_oob_events,
        oob_read_rc = oob_read.rc,
        oob_read_errno = oob_read.err,
        oob_read_hex = oob_hex,
        priority_poll_rc = priority_poll.rc,
        priority_poll_errno = priority_poll.err,
        priority_poll_revents = priority_events,
        tail_rc = tail.rc,
        tail_errno = tail.err,
        tail_hex = tail_hex,
    );
}

/// Clarify zero-length read behavior without assigning it a policy in the
/// runtime first.  Normal and OOB zero-length reads are observed separately.
fn run_zero_length_case() {
    let pair = match open_pair(false) {
        Ok(pair) => pair,
        Err(error) => return emit_setup_error("zero_length", error),
    };
    let sent = send_bytes(pair.server, b"!", libc::MSG_OOB);
    let (initial_poll, initial_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (normal_zero, normal_zero_hex) = recv_len_hex(pair.client, 0, 0);
    let (after_normal_poll, after_normal_events) =
        poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (oob_zero, oob_zero_hex) = recv_len_hex(pair.client, 0, libc::MSG_OOB);
    let (after_oob_zero_poll, after_oob_zero_events) =
        poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (oob_read, oob_read_hex) = recv_hex(pair.client, libc::MSG_OOB);
    unsafe { pair.close() };
    report!(
        oob_case = "zero_length",
        setup_rc = 0,
        send_oob_rc = sent.rc,
        send_oob_errno = sent.err,
        initial_poll_rc = initial_poll.rc,
        initial_poll_errno = initial_poll.err,
        initial_poll_revents = initial_events,
        normal_zero_rc = normal_zero.rc,
        normal_zero_errno = normal_zero.err,
        normal_zero_hex = normal_zero_hex,
        after_normal_poll_rc = after_normal_poll.rc,
        after_normal_poll_errno = after_normal_poll.err,
        after_normal_poll_revents = after_normal_events,
        oob_zero_rc = oob_zero.rc,
        oob_zero_errno = oob_zero.err,
        oob_zero_hex = oob_zero_hex,
        after_oob_zero_poll_rc = after_oob_zero_poll.rc,
        after_oob_zero_poll_errno = after_oob_zero_poll.err,
        after_oob_zero_poll_revents = after_oob_zero_events,
        oob_read_rc = oob_read.rc,
        oob_read_errno = oob_read.err,
        oob_read_hex = oob_read_hex,
    );
}

/// Inline PEEK at the mark must show the virtual urgent byte and suffix while
/// retaining both the mark and priority readiness.
fn run_inline_mark_peek_case() {
    let pair = match open_pair(true) {
        Ok(pair) => pair,
        Err(error) => return emit_setup_error("inline_mark_peek", error),
    };
    let oob = send_bytes(pair.server, b"hello", libc::MSG_OOB);
    let normal = send_bytes(pair.server, b"world", 0);
    let (ready, ready_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (first, first_hex) = recv_hex(pair.client, 0);
    let (mark, mark_value) = atmark(pair.client);
    let (peek, peek_hex) = recv_hex(pair.client, libc::MSG_PEEK);
    let (after_peek_mark, after_peek_mark_value) = atmark(pair.client);
    let (after_peek_poll, after_peek_events) = poll_one(pair.client, libc::POLLIN | libc::POLLPRI);
    let (read, read_hex) = recv_hex(pair.client, 0);
    unsafe { pair.close() };
    report!(
        oob_case = "inline_mark_peek",
        setup_rc = 0,
        send_oob_rc = oob.rc,
        send_oob_errno = oob.err,
        send_normal_rc = normal.rc,
        send_normal_errno = normal.err,
        ready_poll_rc = ready.rc,
        ready_poll_errno = ready.err,
        ready_poll_revents = ready_events,
        first_rc = first.rc,
        first_errno = first.err,
        first_hex = first_hex,
        mark_rc = mark.rc,
        mark_errno = mark.err,
        mark_value = mark_value,
        peek_rc = peek.rc,
        peek_errno = peek.err,
        peek_hex = peek_hex,
        after_peek_mark_rc = after_peek_mark.rc,
        after_peek_mark_errno = after_peek_mark.err,
        after_peek_mark_value = after_peek_mark_value,
        after_peek_poll_rc = after_peek_poll.rc,
        after_peek_poll_errno = after_peek_poll.err,
        after_peek_poll_revents = after_peek_events,
        read_rc = read.rc,
        read_errno = read.err,
        read_hex = read_hex,
    );
}

fn emit(label: &str, result: &Case) {
    report!(
        oob_case = label,
        setup_attempted = result.setup.attempted,
        setup_rc = result.setup.rc,
        setup_errno = result.setup.err,
        connect_attempted = result.connect.attempted,
        connect_rc = result.connect.rc,
        connect_errno = result.connect.err,
        connect_poll_attempted = result.connect_poll.attempted,
        connect_poll_rc = result.connect_poll.rc,
        connect_poll_errno = result.connect_poll.err,
        connect_so_error_attempted = result.connect_so_error.attempted,
        connect_so_error_rc = result.connect_so_error.rc,
        connect_so_error_errno = result.connect_so_error.err,
        connect_so_error_value = result.connect_so_error_value,
        accept_poll_attempted = result.accept_poll.attempted,
        accept_poll_rc = result.accept_poll.rc,
        accept_poll_errno = result.accept_poll.err,
        accept_attempted = result.accept.attempted,
        accept_rc = result.accept.rc,
        accept_errno = result.accept.err,
        set_inline_attempted = result.set_inline.attempted,
        set_inline_rc = result.set_inline.rc,
        set_inline_errno = result.set_inline.err,
        send_oob_attempted = result.send_oob.attempted,
        send_oob_rc = result.send_oob.rc,
        send_oob_errno = result.send_oob.err,
        send_normal_attempted = result.send_normal.attempted,
        send_normal_rc = result.send_normal.rc,
        send_normal_errno = result.send_normal.err,
        ready_poll_attempted = result.ready_poll.attempted,
        ready_poll_rc = result.ready_poll.rc,
        ready_poll_errno = result.ready_poll.err,
        ready_poll_revents = result.ready_revents,
        mark_before_attempted = result.mark_before.attempted,
        mark_before_rc = result.mark_before.rc,
        mark_before_errno = result.mark_before.err,
        mark_before_value = result.mark_before_value,
        normal_first_attempted = result.normal_first.attempted,
        normal_first_rc = result.normal_first.rc,
        normal_first_errno = result.normal_first.err,
        normal_first_hex = result.normal_first_hex,
        mark_after_first_attempted = result.mark_after_first.attempted,
        mark_after_first_rc = result.mark_after_first.rc,
        mark_after_first_errno = result.mark_after_first.err,
        mark_after_first_value = result.mark_after_first_value,
        recv_oob_attempted = result.recv_oob.attempted,
        recv_oob_rc = result.recv_oob.rc,
        recv_oob_errno = result.recv_oob.err,
        recv_oob_hex = result.recv_oob_hex,
        mark_after_oob_attempted = result.mark_after_oob.attempted,
        mark_after_oob_rc = result.mark_after_oob.rc,
        mark_after_oob_errno = result.mark_after_oob.err,
        mark_after_oob_value = result.mark_after_oob_value,
        second_ready_poll_attempted = result.second_ready_poll.attempted,
        second_ready_poll_rc = result.second_ready_poll.rc,
        second_ready_poll_errno = result.second_ready_poll.err,
        second_ready_poll_revents = result.second_ready_revents,
        normal_second_attempted = result.normal_second.attempted,
        normal_second_rc = result.normal_second.rc,
        normal_second_errno = result.normal_second.err,
        normal_second_hex = result.normal_second_hex,
    );
}

fn main() {
    emit("default", &run_case(false));
    emit("inline", &run_case(true));
    run_cross_mark_case();
    run_peek_case();
    run_repeated_case();
    run_toggle_after_arrival_case();
    run_zero_length_case();
    run_inline_mark_peek_case();
}
